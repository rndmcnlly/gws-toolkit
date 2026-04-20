"""
title: Google Workspace
author: Adam Smith
author_url: https://github.com/rndmcnlly/gws-toolkit
description: Per-user, per-chat OAuth2 access to Google Workspace APIs. Ephemeral tokens — every chat starts unauthorized. Admin valves control which capabilities are available. Uses OWUI event emitters for self-contained OAuth authorization.
required_open_webui_version: 0.4.0
version: 0.7.0
licence: MIT
requirements: httpx
"""

import base64
from datetime import datetime, timezone
import hashlib
import html as html_mod
import httpx
import json
import re
import secrets
import time
import urllib.parse
from pydantic import BaseModel, Field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_ID = "gws_toolkit"
TOOL_VERSION = "0.7.0"
ROUTE_PREFIX = f"/api/v1/x/{TOOL_ID}"
CALLBACK_PATH = f"{ROUTE_PREFIX}/oauth/callback"

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# ---------------------------------------------------------------------------
# Capability registry
#
# Each capability maps to a Google OAuth scope.  Names mirror Google's own
# scope suffixes so admins can cross-reference with
# https://developers.google.com/identity/protocols/oauth2/scopes
# ---------------------------------------------------------------------------

CAPABILITIES = {
    # capability_name: (oauth_scope_url, description)
    "drive.readonly": (
        "https://www.googleapis.com/auth/drive.readonly",
        "Search, read, and list Google Drive files",
    ),
    "drive": (
        "https://www.googleapis.com/auth/drive",
        "Full access to Google Drive (read, create, edit, organize, delete)",
    ),
    "gmail.readonly": (
        "https://www.googleapis.com/auth/gmail.readonly",
        "Read Gmail messages and threads",
    ),
    "gmail.compose": (
        "https://www.googleapis.com/auth/gmail.compose",
        "Create and manage email drafts",
    ),
    "calendar.readonly": (
        "https://www.googleapis.com/auth/calendar.readonly",
        "View calendar events",
    ),
    "calendar.events": (
        "https://www.googleapis.com/auth/calendar.events",
        "View and edit calendar events",
    ),
    "spreadsheets.readonly": (
        "https://www.googleapis.com/auth/spreadsheets.readonly",
        "Read Google Sheets data",
    ),
    "spreadsheets": (
        "https://www.googleapis.com/auth/spreadsheets",
        "Read and write Google Sheets data",
    ),
    "tasks.readonly": (
        "https://www.googleapis.com/auth/tasks.readonly",
        "View Google Tasks",
    ),
    "tasks": (
        "https://www.googleapis.com/auth/tasks",
        "Create and manage Google Tasks",
    ),
    "documents.readonly": (
        "https://www.googleapis.com/auth/documents.readonly",
        "Read Google Docs content",
    ),
    "documents": (
        "https://www.googleapis.com/auth/documents",
        "Read and write Google Docs content",
    ),
    "presentations.readonly": (
        "https://www.googleapis.com/auth/presentations.readonly",
        "Read Google Slides content",
    ),
    "presentations": (
        "https://www.googleapis.com/auth/presentations",
        "Read and write Google Slides content",
    ),
}


def _parse_caps(csv: str) -> set:
    """Parse a comma-separated capability string into a validated set."""
    return {c.strip() for c in csv.split(",") if c.strip() in CAPABILITIES}


def _scopes_for_caps(caps: set) -> str:
    """Convert capability names to a space-separated OAuth scope string."""
    return " ".join(CAPABILITIES[c][0] for c in sorted(caps) if c in CAPABILITIES)


def _caps_from_scopes(scope_str: str) -> set:
    """Reverse-map a space-separated scope string back to capability names."""
    scope_to_cap = {v[0]: k for k, v in CAPABILITIES.items()}
    return {scope_to_cap[s] for s in scope_str.split() if s in scope_to_cap}


# ---------------------------------------------------------------------------
# Action registry
#
# Populated by @action decorators on handler functions below.
# Each entry maps action_name -> (required_capability, handler_fn, description)
# Action names mirror the Google API resource paths: {service}.{resource}.{verb}
# ---------------------------------------------------------------------------

ACTIONS: dict = {}  # populated by @action decorators below


def action(name: str, *, cap: str):
    """Register a handler function as a named GWS action."""
    def decorator(fn):
        ACTIONS[name] = (cap, fn, fn.__doc__ or "")
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Route helpers
# (see: https://gist.github.com/rndmcnlly/740a0238962de750c5fd14e606fe8c90)
# ---------------------------------------------------------------------------


def _insert_route_before_spa(app, path: str, endpoint, methods: list[str] = ["GET"]):
    """Register a route and reposition it before the SPAStaticFiles catch-all."""
    app.add_api_route(path, endpoint, methods=methods)
    routes = app.router.routes
    new_route = None
    spa_idx = None
    for i, r in enumerate(routes):
        if hasattr(r, "path") and r.path == path:
            new_route = r
        if type(r).__name__ == "Mount" and getattr(r, "path", None) == "":
            spa_idx = i
    if new_route is not None and spa_idx is not None:
        routes.remove(new_route)
        routes.insert(spa_idx, new_route)


def _strip_tool_routes(app):
    """Remove all routes registered by this tool."""
    app.router.routes = [
        r for r in app.router.routes
        if not (hasattr(r, "path") and r.path.startswith(ROUTE_PREFIX))
    ]


# ---------------------------------------------------------------------------
# Ephemeral per-chat token cache  (in-process only, no DB)
#
# Key: (user_id, chat_id) -> {
#     "access_token": str,
#     "expires_at": float,
#     "granted_caps": set[str],   # capability names granted by Google
# }
# ---------------------------------------------------------------------------


def _app_state_dict(app, suffix: str) -> dict:
    """Lazy-init a named dict on app.state.  Lost on restart — by design."""
    key = f"__{TOOL_ID}_{suffix}__"
    d = getattr(app.state, key, None)
    if d is None:
        d = {}
        setattr(app.state, key, d)
    return d


def _token_cache(app) -> dict:
    """Per-chat token cache."""
    return _app_state_dict(app, "tokens")


def _pending_states(app) -> dict:
    """OAuth state -> {user_id, chat_id} for in-flight flows."""
    return _app_state_dict(app, "pending")


def _get_chat_token(app, user_id: str, chat_id: str) -> Optional[dict]:
    """Return the cached token entry for this chat, or None."""
    entry = _token_cache(app).get((user_id, chat_id))
    if not entry:
        return None
    if entry.get("expires_at", 0) <= time.time():
        # Expired — remove it.  User will need to re-authorize.
        _token_cache(app).pop((user_id, chat_id), None)
        return None
    return entry


def _clear_chat_token(app, user_id: str, chat_id: str):
    """Remove cached token for this chat."""
    _token_cache(app).pop((user_id, chat_id), None)


# ---------------------------------------------------------------------------
# Route registration (version-stamped, idempotent)
# ---------------------------------------------------------------------------


def _routes_version(client_id: str, client_secret: str, base_url: str) -> str:
    # Intentionally excludes TOOL_VERSION — routes only need re-registration
    # when credentials or base URL change, not on code updates.
    h = hashlib.sha256(
        f"{client_id}:{client_secret}:{base_url}".encode())
    return h.hexdigest()[:12]


def _ensure_routes(app, client_id: str, client_secret: str, base_url: str):
    """Register the OAuth callback.  Skips if already current."""
    version_key = f"__{TOOL_ID}_route_version__"
    target = _routes_version(client_id, client_secret, base_url)
    if getattr(app.state, version_key, None) == target:
        return
    _strip_tool_routes(app)

    from fastapi import Request
    from fastapi.responses import HTMLResponse

    redirect_uri = base_url.rstrip("/") + CALLBACK_PATH

    async def oauth_callback(request: Request):
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")

        if error:
            return HTMLResponse(
                f"<h2>Authorization failed</h2><p>{error}</p>", status_code=400)
        if not code or not state:
            return HTMLResponse(
                "<h2>Missing parameters</h2><p>Please try again from the chat.</p>",
                status_code=400)

        pending = _pending_states(request.app)
        flow = pending.pop(state, None)
        if not flow:
            return HTMLResponse(
                "<h2>Expired or invalid state</h2>"
                "<p>Please start the authorization flow again from the chat.</p>",
                status_code=400)

        user_id = flow["user_id"]
        chat_id = flow["chat_id"]

        async with httpx.AsyncClient() as client:
            resp = await client.post(GOOGLE_TOKEN_URL, data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            })

        if resp.status_code != 200:
            return HTMLResponse(
                f"<h2>Token exchange failed</h2><pre>{resp.text[:500]}</pre>",
                status_code=502)

        td = resp.json()
        access_token = td.get("access_token", "")
        scope_str = td.get("scope", "")
        expires_at = time.time() + td.get("expires_in", 3600) - 60

        # Merge newly granted caps with any existing ones for this chat
        newly_granted = _caps_from_scopes(scope_str)
        existing = _get_chat_token(request.app, user_id, chat_id)
        if existing:
            merged_caps = existing.get("granted_caps", set()) | newly_granted
        else:
            merged_caps = newly_granted

        _token_cache(request.app)[(user_id, chat_id)] = {
            "access_token": access_token,
            "expires_at": expires_at,
            "granted_caps": merged_caps,
        }

        cap_list = ", ".join(sorted(merged_caps)) if merged_caps else "(none recognized)"
        return HTMLResponse(
            "<html><head><style>"
            "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
            "display:flex;justify-content:center;align-items:center;min-height:100vh;"
            "margin:0;background:#f9fafb;color:#111827}"
            ".card{background:#fff;border-radius:12px;padding:2.5rem 3rem;"
            "box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center;max-width:420px}"
            ".check{font-size:3rem;margin-bottom:.5rem}"
            "h2{margin:0 0 .5rem;font-size:1.25rem}"
            ".caps{color:#6b7280;font-size:.875rem;margin-bottom:1rem}"
            ".hint{color:#9ca3af;font-size:.8rem}"
            "</style></head><body><div class='card'>"
            "<div class='check'>&#10003;</div>"
            f"<h2>Access granted</h2>"
            f"<div class='caps'>{cap_list}</div>"
            f"<div class='hint'>This access is for the current chat only.<br>"
            f"You can close this tab and return to the chat.</div>"
            "</div></body></html>"
            "<script>window.close()</script>")

    _insert_route_before_spa(app, CALLBACK_PATH, oauth_callback, methods=["GET"])
    setattr(app.state, version_key, target)


# ---------------------------------------------------------------------------
# Setup helper
# ---------------------------------------------------------------------------


def _setup(app, valves):
    """Lazy route registration, called once per tool invocation."""
    if valves.google_client_id and valves.google_client_secret:
        _ensure_routes(
            app, valves.google_client_id,
            valves.google_client_secret, valves.base_url)


# ---------------------------------------------------------------------------
# Authorization URL builder
# ---------------------------------------------------------------------------


def _build_auth_url(
    app, valves, user_id: str, chat_id: str, email: str,
    requested_caps: set,
) -> str:
    """
    Build a Google OAuth consent URL for the given capabilities.
    Registers a pending state nonce for the callback.
    """
    state = secrets.token_urlsafe(32)
    _pending_states(app)[state] = {
        "user_id": user_id,
        "chat_id": chat_id,
    }

    # Check if user already has some scopes in this chat — if so, use
    # incremental auth to add new ones without re-consenting to old ones.
    existing = _get_chat_token(app, user_id, chat_id)
    has_existing = existing is not None and bool(existing.get("granted_caps"))

    params = {
        "client_id": valves.google_client_id,
        "redirect_uri": valves.base_url.rstrip("/") + CALLBACK_PATH,
        "response_type": "code",
        "scope": _scopes_for_caps(requested_caps),
        "access_type": "online",
        "prompt": "consent",
        "state": state,
    }
    if has_existing:
        params["include_granted_scopes"] = "true"
    if email:
        params["login_hint"] = email

    return GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)


# ---------------------------------------------------------------------------
# Action handler helpers
# ---------------------------------------------------------------------------


def _require(params: dict, *names: str) -> str | None:
    """Return an error string if any required param is missing, else None."""
    missing = [n for n in names if not params.get(n)]
    if missing:
        return f"ERROR: Required parameter(s): {', '.join(missing)}"
    return None


async def _gws_request(
    method: str, url: str, token: str, app, user_id, chat_id,
    params=None, body=None, raw=False,
) -> tuple[dict | str | None, str | None]:
    """
    Make an authenticated Google API request.
    Returns (json_or_text, None) on success, or (None, error_string) on failure.
    Set raw=True to return response text instead of parsed JSON.
    """
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    async with httpx.AsyncClient() as client:
        resp = await client.request(method, url, params=params, json=body, headers=headers)
    if resp.status_code == 401:
        _clear_chat_token(app, user_id, chat_id)
        return None, "AUTH_EXPIRED: Token expired. The user must re-authorize for this chat."
    if resp.status_code == 404:
        return None, "NOT_FOUND: The requested resource was not found."
    if resp.status_code != 200:
        return None, f"API_ERROR: {resp.status_code}: {resp.text[:300]}"
    return (resp.text if raw else resp.json()), None


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------


@action("drive.files.search", cap="drive.readonly")
async def _action_drive_search(token: str, params: dict, app, user_id, chat_id) -> str:
    """Search Drive files. Ref: https://developers.google.com/drive/api/reference/rest/v3/files/list Params: query (str, required)"""
    err = _require(params, "query")
    if err:
        return err

    query = params["query"]
    safe_q = query.replace("\\", "\\\\").replace("'", "\\'")
    data, err = await _gws_request(
        "GET", "https://www.googleapis.com/drive/v3/files",
        token, app, user_id, chat_id, params={
            "q": f"fullText contains '{safe_q}' and trashed=false",
            "pageSize": 10,
            "fields": "files(id,name,mimeType,webViewLink,modifiedTime)",
            "orderBy": "modifiedTime desc",
        })
    if err:
        return err

    files = data.get("files", [])
    if not files:
        return f"NO_RESULTS: No files matching '{query}'."

    def fmt(f):
        m = f.get("mimeType", "")
        t = m.split(".")[-1] if "google-apps" in m else m.split("/")[-1]
        return (f"- {f.get('name','?')} | type={t} "
                f"| modified={f.get('modifiedTime','')[:10]} "
                f"| id={f.get('id','')} | link={f.get('webViewLink','')}")

    return f"RESULTS: {len(files)} file(s):\n" + "\n".join(fmt(f) for f in files)


@action("drive.files.get", cap="drive.readonly")
async def _action_drive_read(token: str, params: dict, app, user_id, chat_id) -> str:
    """Read a Drive file (exports Docs as markdown, Sheets as CSV, Slides as text). Ref: https://developers.google.com/drive/api/reference/rest/v3/files/get Params: fileId (str, required)"""
    err = _require(params, "fileId")
    if err:
        return err
    file_id = params["fileId"]

    meta, err = await _gws_request(
        "GET", f"https://www.googleapis.com/drive/v3/files/{file_id}",
        token, app, user_id, chat_id, params={"fields": "id,name,mimeType,size"})
    if err:
        return err

    name = meta.get("name", "Untitled")
    mime = meta.get("mimeType", "")

    export_map = {
        "application/vnd.google-apps.document": "text/markdown",
        "application/vnd.google-apps.spreadsheet": "text/csv",
        "application/vnd.google-apps.presentation": "text/plain",
    }

    if mime in export_map:
        text, err = await _gws_request(
            "GET", f"https://www.googleapis.com/drive/v3/files/{file_id}/export",
            token, app, user_id, chat_id, params={"mimeType": export_map[mime]}, raw=True)
    elif mime.startswith("text/") or mime == "application/json":
        text, err = await _gws_request(
            "GET", f"https://www.googleapis.com/drive/v3/files/{file_id}",
            token, app, user_id, chat_id, params={"alt": "media"}, raw=True)
    elif mime == "application/pdf":
        return (f"FILE_INFO: '{name}' is a PDF (no text extraction). "
                f"Link: https://drive.google.com/file/d/{file_id}/view")
    else:
        return (f"FILE_INFO: '{name}' ({mime}) cannot be read as text. "
                f"Link: https://drive.google.com/file/d/{file_id}/view")

    if err:
        return err

    content = text[:16384]
    trunc = " (TRUNCATED)" if len(text) > 16384 else ""
    return f"FILE_CONTENT: name='{name}'{trunc}\n\n{content}"


@action("drive.files.list", cap="drive.readonly")
async def _action_drive_list(token: str, params: dict, app, user_id, chat_id) -> str:
    """List files in a Drive folder. Ref: https://developers.google.com/drive/api/reference/rest/v3/files/list Params: folderId (str, default 'root')"""
    folder_id = params.get("folderId", "root")

    data, err = await _gws_request(
        "GET", "https://www.googleapis.com/drive/v3/files",
        token, app, user_id, chat_id, params={
            "q": f"'{folder_id}' in parents and trashed=false",
            "pageSize": 50,
            "fields": "files(id,name,mimeType,modifiedTime)",
            "orderBy": "folder,name",
        })
    if err:
        return err

    files = data.get("files", [])
    if not files:
        return "EMPTY: Folder contains no items."

    def fmt(f):
        m = f.get("mimeType", "")
        k = "folder" if m == "application/vnd.google-apps.folder" else (
            m.split(".")[-1] if "google-apps" in m else m.split("/")[-1])
        return (f"- {f.get('name','?')} | type={k} "
                f"| modified={f.get('modifiedTime','')[:10]} | id={f.get('id','')}")

    return f"LISTING: {len(files)} item(s):\n" + "\n".join(fmt(f) for f in files)


# ---------------------------------------------------------------------------
# Gmail helpers
# ---------------------------------------------------------------------------


def _decode_mime_body(payload: dict) -> str:
    """Extract readable text from a Gmail message payload (recursive MIME walk)."""
    # Direct body on this part
    body_data = payload.get("body", {}).get("data", "")
    mime_type = payload.get("mimeType", "")

    # Leaf node with data
    if body_data and not payload.get("parts"):
        decoded = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")
        if mime_type == "text/plain":
            return decoded
        if mime_type == "text/html":
            # Strip HTML tags to get readable text
            text = re.sub(r"<style[^>]*>.*?</style>", "", decoded, flags=re.DOTALL)
            text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL)
            text = re.sub(r"<[^>]+>", " ", text)
            text = html_mod.unescape(text)
            text = re.sub(r"\s+", " ", text).strip()
            return text
        return decoded

    # Multipart — recurse, preferring text/plain
    parts = payload.get("parts", [])
    plain_parts = []
    html_parts = []
    other_parts = []
    for part in parts:
        mt = part.get("mimeType", "")
        if mt == "text/plain" or mt.startswith("multipart/"):
            plain_parts.append(part)
        elif mt == "text/html":
            html_parts.append(part)
        else:
            other_parts.append(part)

    # Try plain first, then html, then anything
    for group in [plain_parts, html_parts, other_parts]:
        for part in group:
            result = _decode_mime_body(part)
            if result.strip():
                return result

    return "(no readable body)"


def _extract_header(headers: list, name: str) -> str:
    """Extract a header value by name from a Gmail headers list."""
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


def _format_message_summary(msg: dict) -> str:
    """Format a Gmail message into a one-line summary."""
    headers = msg.get("payload", {}).get("headers", [])
    from_ = _extract_header(headers, "From")
    subject = _extract_header(headers, "Subject")
    date = _extract_header(headers, "Date")
    snippet = msg.get("snippet", "")
    msg_id = msg.get("id", "")
    return (f"- from={from_} | subject={subject} | date={date} "
            f"| id={msg_id}\n  {snippet}")


def _format_message_full(msg: dict) -> str:
    """Format a Gmail message with headers and decoded body."""
    headers = msg.get("payload", {}).get("headers", [])
    from_ = _extract_header(headers, "From")
    to = _extract_header(headers, "To")
    subject = _extract_header(headers, "Subject")
    date = _extract_header(headers, "Date")
    cc = _extract_header(headers, "Cc")

    body = _decode_mime_body(msg.get("payload", {}))
    if len(body) > 8192:
        body = body[:8192] + "\n\n(TRUNCATED)"

    header_block = f"From: {from_}\nTo: {to}\nDate: {date}\nSubject: {subject}"
    if cc:
        header_block += f"\nCc: {cc}"

    return f"{header_block}\n\n{body}"


# ---------------------------------------------------------------------------
# Gmail action handlers
# ---------------------------------------------------------------------------


@action("gmail.messages.search", cap="gmail.readonly")
async def _action_gmail_messages_search(token: str, params: dict, app, user_id, chat_id) -> str:
    """Search Gmail messages (uses Gmail search syntax: from:, subject:, after:, etc.). Ref: https://developers.google.com/gmail/api/reference/rest/v1/users.messages/list Params: query (str), maxResults (int, default 10)"""
    query = params.get("query", "")
    max_results = min(int(params.get("maxResults", 10)), 20)

    api_params = {"userId": "me", "maxResults": max_results}
    if query:
        api_params["q"] = query

    data, err = await _gws_request(
        "GET", "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        token, app, user_id, chat_id, params=api_params)
    if err:
        return err

    message_stubs = data.get("messages", [])
    if not message_stubs:
        return f"NO_RESULTS: No messages matching '{query}'."

    # Fetch metadata for each message sequentially
    results = []
    for stub in message_stubs:
        msg, err = await _gws_request(
            "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{stub['id']}",
            token, app, user_id, chat_id,
            params={"format": "metadata",
                    "metadataHeaders": ["From", "Subject", "Date"]})
        if msg:
            msg["snippet"] = msg.get("snippet", "")
            results.append(_format_message_summary(msg))

    return f"RESULTS: {len(results)} message(s):\n" + "\n".join(results)


@action("gmail.messages.get", cap="gmail.readonly")
async def _action_gmail_messages_get(token: str, params: dict, app, user_id, chat_id) -> str:
    """Read a single Gmail message with decoded body. Ref: https://developers.google.com/gmail/api/reference/rest/v1/users.messages/get Params: messageId (str, required)"""
    err = _require(params, "messageId")
    if err:
        return err

    data, err = await _gws_request(
        "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{params['messageId']}",
        token, app, user_id, chat_id, params={"format": "full"})
    if err:
        return err

    return "MESSAGE:\n" + _format_message_full(data)


@action("gmail.threads.list", cap="gmail.readonly")
async def _action_gmail_threads_list(token: str, params: dict, app, user_id, chat_id) -> str:
    """Search Gmail threads. Ref: https://developers.google.com/gmail/api/reference/rest/v1/users.threads/list Params: query (str), maxResults (int, default 10)"""
    query = params.get("query", "")
    max_results = min(int(params.get("maxResults", 10)), 20)

    api_params = {"userId": "me", "maxResults": max_results}
    if query:
        api_params["q"] = query

    data, err = await _gws_request(
        "GET", "https://gmail.googleapis.com/gmail/v1/users/me/threads",
        token, app, user_id, chat_id, params=api_params)
    if err:
        return err

    threads = data.get("threads", [])
    if not threads:
        return f"NO_RESULTS: No threads matching '{query}'."

    lines = []
    for t in threads:
        snippet = t.get("snippet", "")
        lines.append(f"- id={t['id']} | {snippet[:120]}")

    return f"RESULTS: {len(threads)} thread(s):\n" + "\n".join(lines)


@action("gmail.threads.get", cap="gmail.readonly")
async def _action_gmail_threads_get(token: str, params: dict, app, user_id, chat_id) -> str:
    """Read all messages in a Gmail thread. Ref: https://developers.google.com/gmail/api/reference/rest/v1/users.threads/get Params: threadId (str, required)"""
    err = _require(params, "threadId")
    if err:
        return err

    data, err = await _gws_request(
        "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/threads/{params['threadId']}",
        token, app, user_id, chat_id, params={"format": "full"})
    if err:
        return err

    messages = data.get("messages", [])
    if not messages:
        return "EMPTY: Thread contains no messages."

    parts = [f"THREAD: {len(messages)} message(s)\n"]
    for i, msg in enumerate(messages, 1):
        parts.append(f"--- Message {i}/{len(messages)} ---")
        parts.append(_format_message_full(msg))

    result = "\n\n".join(parts)
    if len(result) > 32768:
        result = result[:32768] + "\n\n(TRUNCATED)"
    return result


# ---------------------------------------------------------------------------
# Gmail draft action handlers
# ---------------------------------------------------------------------------

GMAIL_DRAFTS_API = "https://gmail.googleapis.com/gmail/v1/users/me/drafts"


def _build_rfc2822_base64(to: str, subject: str, body: str,
                          cc: str = "", bcc: str = "",
                          in_reply_to: str = "", references: str = "") -> str:
    """Build an RFC 2822 message and return it as a URL-safe base64 string.

    Uses email.message.EmailMessage from stdlib for correct header encoding
    (handles non-ASCII subjects, long lines, etc.).
    """
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["To"] = to
    msg["Subject"] = subject
    if cc:
        msg["Cc"] = cc
    if bcc:
        msg["Bcc"] = bcc
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    msg.set_content(body)
    raw_bytes = msg.as_bytes()
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii")


@action("gmail.drafts.create", cap="gmail.compose")
async def _action_gmail_drafts_create(token: str, params: dict, app, user_id, chat_id) -> str:
    """Create a Gmail draft (does NOT send). Ref: https://developers.google.com/gmail/api/reference/rest/v1/users.drafts/create Params: to (str, required), subject (str, required), body (str, required), cc (str), bcc (str), threadId (str — set to reply within an existing thread), inReplyTo (str — Message-ID header of the message being replied to), references (str — References header for threading)"""
    err = _require(params, "to", "subject", "body")
    if err:
        return err

    raw = _build_rfc2822_base64(
        to=params["to"],
        subject=params["subject"],
        body=params["body"],
        cc=params.get("cc", ""),
        bcc=params.get("bcc", ""),
        in_reply_to=params.get("inReplyTo", ""),
        references=params.get("references", ""),
    )

    request_body = {"message": {"raw": raw}}
    if params.get("threadId"):
        request_body["message"]["threadId"] = params["threadId"]

    data, err = await _gws_request(
        "POST", GMAIL_DRAFTS_API,
        token, app, user_id, chat_id, body=request_body)
    if err:
        return err

    draft_id = data.get("id", "?")
    msg_data = data.get("message", {})
    thread_id = msg_data.get("threadId", "")

    return (
        f"DRAFT_CREATED: Draft saved successfully.\n"
        f"  draftId={draft_id}\n"
        f"  threadId={thread_id}\n"
        f"The user can review and send it from Gmail."
    )


@action("gmail.drafts.list", cap="gmail.readonly")
async def _action_gmail_drafts_list(token: str, params: dict, app, user_id, chat_id) -> str:
    """List Gmail drafts. Ref: https://developers.google.com/gmail/api/reference/rest/v1/users.drafts/list Params: query (str — Gmail search syntax), maxResults (int, default 10)"""
    max_results = min(int(params.get("maxResults", 10)), 20)
    api_params = {"userId": "me", "maxResults": max_results}
    q = params.get("query", "")
    if q:
        api_params["q"] = q

    data, err = await _gws_request(
        "GET", GMAIL_DRAFTS_API,
        token, app, user_id, chat_id, params=api_params)
    if err:
        return err

    drafts = data.get("drafts", [])
    if not drafts:
        return "NO_RESULTS: No drafts found."

    # Fetch summary metadata for each draft
    lines = []
    for d in drafts:
        draft_id = d.get("id", "?")
        msg_stub = d.get("message", {})
        msg_id = msg_stub.get("id", "")

        if msg_id:
            msg, _ = await _gws_request(
                "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}",
                token, app, user_id, chat_id,
                params={"format": "metadata",
                        "metadataHeaders": ["To", "Subject", "Date"]})
            if msg:
                headers = msg.get("payload", {}).get("headers", [])
                to = _extract_header(headers, "To")
                subject = _extract_header(headers, "Subject")
                snippet = msg.get("snippet", "")
                lines.append(
                    f"- draftId={draft_id} | to={to} | subject={subject}\n"
                    f"  {snippet[:120]}")
                continue

        lines.append(f"- draftId={draft_id} | (no metadata)")

    return f"RESULTS: {len(drafts)} draft(s):\n" + "\n".join(lines)


@action("gmail.drafts.get", cap="gmail.readonly")
async def _action_gmail_drafts_get(token: str, params: dict, app, user_id, chat_id) -> str:
    """Read a specific Gmail draft with decoded body. Ref: https://developers.google.com/gmail/api/reference/rest/v1/users.drafts/get Params: draftId (str, required)"""
    err = _require(params, "draftId")
    if err:
        return err

    data, err = await _gws_request(
        "GET", f"{GMAIL_DRAFTS_API}/{params['draftId']}",
        token, app, user_id, chat_id, params={"format": "full"})
    if err:
        return err

    msg = data.get("message", {})
    if not msg:
        return "ERROR: Draft contains no message data."

    return f"DRAFT (id={data.get('id', '?')}):\n" + _format_message_full(msg)


# ---------------------------------------------------------------------------
# Calendar action handlers
# ---------------------------------------------------------------------------


def _format_event_summary(event: dict) -> str:
    """Format a calendar event into a summary line."""
    summary = event.get("summary", "(no title)")
    start = event.get("start", {})
    start_str = start.get("dateTime", start.get("date", "?"))
    end = event.get("end", {})
    end_str = end.get("dateTime", end.get("date", ""))
    location = event.get("location", "")
    event_id = event.get("id", "")

    line = f"- {summary} | start={start_str}"
    if end_str:
        line += f" | end={end_str}"
    if location:
        line += f" | location={location}"
    line += f" | id={event_id}"
    return line


def _format_event_full(event: dict) -> str:
    """Format a calendar event with full details."""
    summary = event.get("summary", "(no title)")
    start = event.get("start", {})
    start_str = start.get("dateTime", start.get("date", "?"))
    end = event.get("end", {})
    end_str = end.get("dateTime", end.get("date", ""))
    location = event.get("location", "")
    description = event.get("description", "")
    status = event.get("status", "")
    organizer = event.get("organizer", {}).get("email", "")
    html_link = event.get("htmlLink", "")
    hangout = event.get("hangoutLink", "")
    conference = ""
    for entry_point in event.get("conferenceData", {}).get("entryPoints", []):
        if entry_point.get("entryPointType") == "video":
            conference = entry_point.get("uri", "")
            break

    attendees = event.get("attendees", [])
    attendee_strs = []
    for a in attendees[:20]:
        name = a.get("displayName", a.get("email", "?"))
        resp_status = a.get("responseStatus", "")
        attendee_strs.append(f"  {name} ({resp_status})")

    lines = [f"Event: {summary}"]
    lines.append(f"When: {start_str} to {end_str}")
    if location:
        lines.append(f"Location: {location}")
    if organizer:
        lines.append(f"Organizer: {organizer}")
    if status:
        lines.append(f"Status: {status}")
    if conference:
        lines.append(f"Video: {conference}")
    elif hangout:
        lines.append(f"Hangout: {hangout}")
    if html_link:
        lines.append(f"Link: {html_link}")
    if attendee_strs:
        lines.append(f"Attendees ({len(attendees)}):")
        lines.extend(attendee_strs)
    if description:
        if len(description) > 2000:
            description = description[:2000] + "... (truncated)"
        lines.append(f"\nDescription:\n{description}")

    return "\n".join(lines)


@action("calendar.calendars.list", cap="calendar.readonly")
async def _action_calendar_calendars_list(token: str, params: dict, app, user_id, chat_id) -> str:
    """List the user's calendars (primary, shared, subscribed). Ref: https://developers.google.com/calendar/api/v3/reference/calendarList/list Params: (none)"""
    data, err = await _gws_request(
        "GET", "https://www.googleapis.com/calendar/v3/users/me/calendarList",
        token, app, user_id, chat_id, params={"maxResults": 100})
    if err:
        return err

    calendars = data.get("items", [])
    if not calendars:
        return "EMPTY: No calendars found."

    lines = []
    for cal in calendars:
        primary = " (PRIMARY)" if cal.get("primary") else ""
        access = cal.get("accessRole", "")
        lines.append(f"- {cal.get('summary', '?')}{primary} | access={access} | id={cal.get('id', '')}")

    return f"CALENDARS: {len(calendars)} calendar(s):\n" + "\n".join(lines)


@action("calendar.events.list", cap="calendar.readonly")
async def _action_calendar_events_list(token: str, params: dict, app, user_id, chat_id) -> str:
    """List or search calendar events. Ref: https://developers.google.com/calendar/api/v3/reference/events/list Params: calendarId (str, default 'primary'), q (str), timeMin (ISO 8601, defaults to now), timeMax (ISO 8601), maxResults (int, default 20)"""
    calendar_id = params.get("calendarId", "primary")
    query = params.get("q", "")
    time_min = params.get("timeMin", "")
    time_max = params.get("timeMax", "")
    max_results = min(int(params.get("maxResults", 20)), 50)

    # Default time_min to now — without this, singleEvents=true expands
    # recurring events from their origin (e.g. birthday events from birth
    # year), flooding results with historical instances.
    if not time_min:
        time_min = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    api_params = {
        "calendarId": calendar_id,
        "maxResults": max_results,
        "singleEvents": "true",
        "orderBy": "startTime",
        "timeMin": time_min,
    }
    if query:
        api_params["q"] = query
    if time_max:
        api_params["timeMax"] = time_max

    data, err = await _gws_request(
        "GET", f"https://www.googleapis.com/calendar/v3/calendars/{calendar_id}/events",
        token, app, user_id, chat_id, params=api_params)
    if err:
        return err

    events = data.get("items", [])
    if not events:
        return "NO_RESULTS: No events found for the given criteria."

    lines = [_format_event_summary(e) for e in events]
    return f"EVENTS: {len(events)} event(s):\n" + "\n".join(lines)


@action("calendar.events.get", cap="calendar.readonly")
async def _action_calendar_events_get(token: str, params: dict, app, user_id, chat_id) -> str:
    """Get full details of a calendar event. Ref: https://developers.google.com/calendar/api/v3/reference/events/get Params: eventId (str, required), calendarId (str, default 'primary')"""
    err = _require(params, "eventId")
    if err:
        return err
    calendar_id = params.get("calendarId", "primary")

    data, err = await _gws_request(
        "GET", f"https://www.googleapis.com/calendar/v3/calendars/{calendar_id}/events/{params['eventId']}",
        token, app, user_id, chat_id)
    if err:
        return err

    return "EVENT:\n" + _format_event_full(data)


@action("calendar.freebusy.query", cap="calendar.readonly")
async def _action_calendar_freebusy_query(token: str, params: dict, app, user_id, chat_id) -> str:
    """Check free/busy status for a time range. Ref: https://developers.google.com/calendar/api/v3/reference/freebusy/query Params: timeMin (ISO 8601, required), timeMax (ISO 8601, required), calendarIds (list or comma-separated str, default ['primary'])"""
    time_min = params.get("timeMin", "")
    time_max = params.get("timeMax", "")
    if not time_min or not time_max:
        return "ERROR: 'timeMin' and 'timeMax' parameters are required (ISO 8601, e.g. '2026-04-03T09:00:00-07:00')."

    # Default to primary calendar if none specified
    calendar_ids = params.get("calendarIds", ["primary"])
    if isinstance(calendar_ids, str):
        calendar_ids = [c.strip() for c in calendar_ids.split(",")]

    data, err = await _gws_request(
        "POST", "https://www.googleapis.com/calendar/v3/freeBusy",
        token, app, user_id, chat_id,
        body={
            "timeMin": time_min,
            "timeMax": time_max,
            "items": [{"id": cid} for cid in calendar_ids],
        })
    if err:
        return err
    calendars = data.get("calendars", {})

    lines = [f"FREE/BUSY: {time_min} to {time_max}\n"]
    for cal_id, info in calendars.items():
        errors = info.get("errors", [])
        if errors:
            lines.append(f"  {cal_id}: ERROR — {errors[0].get('reason', '?')}")
            continue
        busy = info.get("busy", [])
        if not busy:
            lines.append(f"  {cal_id}: FREE (no busy periods)")
        else:
            lines.append(f"  {cal_id}: {len(busy)} busy period(s):")
            for period in busy:
                lines.append(f"    {period.get('start', '?')} to {period.get('end', '?')}")

    return "\n".join(lines)


CALENDAR_EVENTS_API = "https://www.googleapis.com/calendar/v3/calendars"


@action("calendar.events.create", cap="calendar.events")
async def _action_calendar_events_create(token: str, params: dict, app, user_id, chat_id) -> str:
    """Create a calendar event. Ref: https://developers.google.com/calendar/api/v3/reference/events/insert Params: calendarId (str, default 'primary'), summary (str, required — event title), start (object, required — e.g. {"dateTime": "2026-04-10T10:00:00-07:00"} or {"date": "2026-04-10"} for all-day), end (object, required — same format as start), description (str), location (str), attendees (list of {"email": "..."}), recurrence (list of RRULE strings, e.g. ["RRULE:FREQ=WEEKLY;COUNT=5"]), sendUpdates (str — 'all', 'externalOnly', or 'none', default 'none')"""
    err = _require(params, "summary", "start", "end")
    if err:
        return err

    calendar_id = params.pop("calendarId", "primary")
    send_updates = params.pop("sendUpdates", "none")

    # Everything remaining in params becomes the event body
    data, err = await _gws_request(
        "POST", f"{CALENDAR_EVENTS_API}/{calendar_id}/events",
        token, app, user_id, chat_id,
        params={"sendUpdates": send_updates},
        body=params)
    if err:
        return err

    return "EVENT_CREATED:\n" + _format_event_full(data)


@action("calendar.events.patch", cap="calendar.events")
async def _action_calendar_events_patch(token: str, params: dict, app, user_id, chat_id) -> str:
    """Update specific fields of an existing calendar event (patch semantics — only include fields to change). Ref: https://developers.google.com/calendar/api/v3/reference/events/patch Params: eventId (str, required), calendarId (str, default 'primary'), sendUpdates (str — 'all', 'externalOnly', or 'none', default 'none'), plus any Event fields to update: summary (str), start (object), end (object), description (str), location (str), attendees (list of {"email": "..."}), recurrence (list of RRULE strings), etc."""
    err = _require(params, "eventId")
    if err:
        return err

    calendar_id = params.pop("calendarId", "primary")
    event_id = params.pop("eventId")
    send_updates = params.pop("sendUpdates", "none")

    data, err = await _gws_request(
        "PATCH", f"{CALENDAR_EVENTS_API}/{calendar_id}/events/{event_id}",
        token, app, user_id, chat_id,
        params={"sendUpdates": send_updates},
        body=params)
    if err:
        return err

    return "EVENT_UPDATED:\n" + _format_event_full(data)


@action("calendar.events.delete", cap="calendar.events")
async def _action_calendar_events_delete(token: str, params: dict, app, user_id, chat_id) -> str:
    """Delete a calendar event. Ref: https://developers.google.com/calendar/api/v3/reference/events/delete Params: eventId (str, required), calendarId (str, default 'primary'), sendUpdates (str — 'all', 'externalOnly', or 'none', default 'none')"""
    err = _require(params, "eventId")
    if err:
        return err

    calendar_id = params.get("calendarId", "primary")
    event_id = params["eventId"]
    send_updates = params.get("sendUpdates", "none")

    # DELETE returns 204 with no body; _gws_request expects 200,
    # so we handle this directly.
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        resp = await client.delete(
            f"{CALENDAR_EVENTS_API}/{calendar_id}/events/{event_id}",
            params={"sendUpdates": send_updates},
            headers=headers)

    if resp.status_code == 204:
        return f"EVENT_DELETED: Event {event_id} has been deleted."
    if resp.status_code == 401:
        _clear_chat_token(app, user_id, chat_id)
        return "AUTH_EXPIRED: Token expired. The user must re-authorize for this chat."
    if resp.status_code == 404:
        return f"NOT_FOUND: Event {event_id} was not found."
    return f"API_ERROR: {resp.status_code}: {resp.text[:300]}"


# ---------------------------------------------------------------------------
# Sheets action handlers
# ---------------------------------------------------------------------------

SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"


@action("sheets.spreadsheets.get", cap="spreadsheets.readonly")
async def _action_sheets_spreadsheets_get(token: str, params: dict, app, user_id, chat_id) -> str:
    """Get spreadsheet metadata: sheet names, row/column counts, named ranges. Ref: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets/get Params: spreadsheetId (str, required)"""
    err = _require(params, "spreadsheetId")
    if err:
        return err
    spreadsheet_id = params["spreadsheetId"]

    data, err = await _gws_request(
        "GET", f"{SHEETS_API}/{spreadsheet_id}",
        token, app, user_id, chat_id,
        params={"fields": "spreadsheetId,properties.title,sheets.properties,namedRanges"})
    if err:
        return err
    title = data.get("properties", {}).get("title", "(untitled)")
    sheets = data.get("sheets", [])
    named_ranges = data.get("namedRanges", [])

    lines = [f"SPREADSHEET: {title} ({spreadsheet_id})", ""]
    lines.append(f"Sheets ({len(sheets)}):")
    for s in sheets:
        props = s.get("properties", {})
        name = props.get("title", "?")
        grid = props.get("gridProperties", {})
        rows = grid.get("rowCount", "?")
        cols = grid.get("columnCount", "?")
        sheet_id = props.get("sheetId", "?")
        lines.append(f"  - {name} | {rows} rows x {cols} cols | sheetId={sheet_id}")

    if named_ranges:
        lines.append(f"\nNamed ranges ({len(named_ranges)}):")
        for nr in named_ranges:
            name = nr.get("name", "?")
            r = nr.get("range", {})
            lines.append(f"  - {name} → sheetId={r.get('sheetId', '?')} "
                         f"rows {r.get('startRowIndex', '?')}:{r.get('endRowIndex', '?')} "
                         f"cols {r.get('startColumnIndex', '?')}:{r.get('endColumnIndex', '?')}")

    return "\n".join(lines)


def _format_values_grid(values: list, range_label: str = "") -> str:
    """Format a 2D values array as a readable aligned table."""
    if not values:
        return f"{range_label}: (empty)" if range_label else "(empty range)"

    # Compute column widths
    max_cols = max(len(row) for row in values)
    widths = [0] * max_cols
    for row in values:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    # Cap column widths at 40 chars for readability
    widths = [min(w, 40) for w in widths]

    lines = []
    if range_label:
        lines.append(f"{range_label} ({len(values)} rows):")

    for row_idx, row in enumerate(values):
        cells = []
        for i in range(max_cols):
            val = str(row[i]) if i < len(row) else ""
            if len(val) > 40:
                val = val[:37] + "..."
            cells.append(val.ljust(widths[i]))
        lines.append("  " + " | ".join(cells))

        # Separator after first row (headers)
        if row_idx == 0:
            lines.append("  " + "-+-".join("-" * w for w in widths))

        # Truncate output for very large ranges
        if row_idx >= 99:
            lines.append(f"  ... ({len(values) - 100} more rows)")
            break

    return "\n".join(lines)


@action("sheets.values.get", cap="spreadsheets.readonly")
async def _action_sheets_values_get(token: str, params: dict, app, user_id, chat_id) -> str:
    """Read a cell range as rows of values. Ref: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values/get Params: spreadsheetId (str, required), range (str, required, e.g. 'Sheet1!A1:D20')"""
    err = _require(params, "spreadsheetId", "range")
    if err:
        return err
    spreadsheet_id = params["spreadsheetId"]
    range_ = params["range"]

    data, err = await _gws_request(
        "GET", f"{SHEETS_API}/{spreadsheet_id}/values/{range_}",
        token, app, user_id, chat_id,
        params={"valueRenderOption": "FORMATTED_VALUE"})
    if err:
        return err
    values = data.get("values", [])
    actual_range = data.get("range", range_)

    return _format_values_grid(values, actual_range)


@action("sheets.values.batchGet", cap="spreadsheets.readonly")
async def _action_sheets_values_batch_get(token: str, params: dict, app, user_id, chat_id) -> str:
    """Read multiple cell ranges in one call. Ref: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values/batchGet Params: spreadsheetId (str, required), ranges (list of str, required, e.g. ['Sheet1!A1:B5', 'Sheet2!C1:C100'])"""
    err = _require(params, "spreadsheetId", "ranges")
    if err:
        return err
    spreadsheet_id = params["spreadsheetId"]
    ranges = params["ranges"]
    if isinstance(ranges, str):
        ranges = [r.strip() for r in ranges.split(",")]

    # httpx handles repeated params via list of tuples
    param_tuples = [("valueRenderOption", "FORMATTED_VALUE")]
    for r in ranges:
        param_tuples.append(("ranges", r))

    data, err = await _gws_request(
        "GET", f"{SHEETS_API}/{spreadsheet_id}/values:batchGet",
        token, app, user_id, chat_id, params=param_tuples)
    if err:
        return err
    value_ranges = data.get("valueRanges", [])

    if not value_ranges:
        return "NO_RESULTS: No data returned for the requested ranges."

    parts = []
    for vr in value_ranges:
        actual_range = vr.get("range", "?")
        values = vr.get("values", [])
        parts.append(_format_values_grid(values, actual_range))

    return "\n\n".join(parts)


@action("sheets.values.update", cap="spreadsheets")
async def _action_sheets_values_update(token: str, params: dict, app, user_id, chat_id) -> str:
    """Write values to a cell range (overwrites existing data). Ref: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values/update Params: spreadsheetId (str, required), range (str, required, A1 notation e.g. 'Sheet1!A1:C3'), values (list of lists, required — each inner list is a row), valueInputOption (str, default 'USER_ENTERED' — use 'RAW' to store strings literally)"""
    err = _require(params, "spreadsheetId", "range", "values")
    if err:
        return err
    spreadsheet_id = params["spreadsheetId"]
    range_ = params["range"]
    values = params["values"]
    value_input = params.get("valueInputOption", "USER_ENTERED")

    data, err = await _gws_request(
        "PUT", f"{SHEETS_API}/{spreadsheet_id}/values/{range_}",
        token, app, user_id, chat_id,
        params={"valueInputOption": value_input},
        body={"range": range_, "majorDimension": "ROWS", "values": values})
    if err:
        return err

    return (
        f"UPDATED: {data.get('updatedRange', range_)} — "
        f"{data.get('updatedRows', '?')} rows, "
        f"{data.get('updatedColumns', '?')} columns, "
        f"{data.get('updatedCells', '?')} cells updated."
    )


@action("sheets.values.append", cap="spreadsheets")
async def _action_sheets_values_append(token: str, params: dict, app, user_id, chat_id) -> str:
    """Append rows after the last row of a table detected in the range. Ref: https://developers.google.com/sheets/api/reference/rest/v4/spreadsheets.values/append Params: spreadsheetId (str, required), range (str, required, A1 notation — defines where to search for the table, e.g. 'Sheet1!A:C'), values (list of lists, required — each inner list is a row), valueInputOption (str, default 'USER_ENTERED'), insertDataOption (str, default 'INSERT_ROWS' — use 'OVERWRITE' to write over cells below the table)"""
    err = _require(params, "spreadsheetId", "range", "values")
    if err:
        return err
    spreadsheet_id = params["spreadsheetId"]
    range_ = params["range"]
    values = params["values"]
    value_input = params.get("valueInputOption", "USER_ENTERED")
    insert_opt = params.get("insertDataOption", "INSERT_ROWS")

    data, err = await _gws_request(
        "POST", f"{SHEETS_API}/{spreadsheet_id}/values/{range_}:append",
        token, app, user_id, chat_id,
        params={"valueInputOption": value_input, "insertDataOption": insert_opt},
        body={"range": range_, "majorDimension": "ROWS", "values": values})
    if err:
        return err

    updates = data.get("updates", {})
    table_range = data.get("tableRange", "")
    updated_range = updates.get("updatedRange", "?")
    updated_rows = updates.get("updatedRows", "?")
    updated_cells = updates.get("updatedCells", "?")

    result = f"APPENDED: {updated_rows} rows, {updated_cells} cells written at {updated_range}."
    if table_range:
        result += f" Table detected at {table_range}."
    return result



# ---------------------------------------------------------------------------
# Build the dynamic docstring for gws_action
# ---------------------------------------------------------------------------

def _build_action_docs() -> str:
    """Generate the docstring listing available actions and their capabilities."""
    lines = [
        "Execute a Google Workspace action.  Available actions "
        "(subject to admin-enabled capabilities):\n",
    ]
    by_service = {}
    for action_name, (cap, _, desc) in sorted(ACTIONS.items()):
        service = action_name.split(".")[0]
        by_service.setdefault(service, []).append((action_name, cap, desc))

    for service, actions in sorted(by_service.items()):
        lines.append(f"  {service.upper()}:")
        for action_name, cap, desc in actions:
            lines.append(f"    {action_name} (requires {cap}): {desc}")

    lines.append(
        "\n:param action: Action name (e.g. 'drive.files.search')"
        "\n:param params: JSON object of action-specific parameters"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The Tool
# ---------------------------------------------------------------------------


class Tools:

    class Valves(BaseModel):
        google_client_id: str = Field(
            default="", description="OAuth2 Web Application client ID")
        google_client_secret: str = Field(
            default="", description="OAuth2 Web Application client secret",
            json_schema_extra={"input": {"type": "password"}})
        base_url: str = Field(
            default="https://chat.adamsmith.as",
            description="Public base URL of this Open WebUI instance")
        # TODO: Consider replacing this comma-separated string with
        # individual bool valves per capability (14 toggles).  OWUI renders
        # bools as toggle switches, which would give admins a cleaner UI.
        # Kept as a single string for now to minimize valve clutter while
        # only Drive actions are implemented.
        enabled_capabilities: str = Field(
            default="drive.readonly",
            description=(
                "Comma-separated Google API capabilities to allow.  "
                "These set the maximum scope any user can authorize.  "
                "Options: " + ", ".join(sorted(CAPABILITIES.keys()))
            ))

    def __init__(self):
        self.valves = self.Valves()

    # -------------------------------------------------------------------
    # Tool: gws_authorize
    # -------------------------------------------------------------------

    async def gws_authorize(
        self,
        capabilities: str = "",
        __user__: dict = {},
        __chat_id__: str = "",
        __request__=None,
        __event_call__=None,
    ) -> str:
        """
        Request Google Workspace authorization for this chat, or inspect
        current authorization status.

        If capabilities is empty, returns the current chat's granted
        capabilities and the admin-allowed maximum.

        If capabilities is non-empty, initiates an OAuth flow for the
        requested capabilities.  The user will see a Google consent screen.

        :param capabilities: Comma-separated capabilities to authorize (e.g. 'drive.readonly' or 'drive.readonly,calendar.readonly').  Leave empty to check status.
        """
        if not __request__:
            return "ERROR: No request context."
        app = __request__.app
        _setup(app, self.valves)

        if not self.valves.google_client_id:
            return "ERROR: Tool not configured. Admin must set OAuth client ID and secret."

        if not __chat_id__:
            return "ERROR: No chat context available."

        user_id = __user__["id"]
        email = __user__.get("email", "")

        admin_caps = _parse_caps(self.valves.enabled_capabilities)
        requested = _parse_caps(capabilities)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        time_line = f"  Current server time (UTC): {now}"

        # Empty request → status introspection
        if not requested:
            existing = _get_chat_token(app, user_id, __chat_id__)
            granted = sorted(existing.get("granted_caps", set())) if existing else []
            available = sorted(admin_caps)

            lines = ["STATUS:"]
            if granted:
                lines.append(f"  Authorized in this chat: {', '.join(granted)}")
            else:
                lines.append("  Authorized in this chat: (none)")
            lines.append(f"  Admin-allowed capabilities: {', '.join(available)}")
            lines.append(time_line)
            return "\n".join(lines)

        disallowed = requested - admin_caps
        if disallowed:
            return (
                f"NOT_ENABLED: Capability {', '.join(sorted(disallowed))} "
                f"not enabled by admin. "
                f"Admin-enabled capabilities: {', '.join(sorted(admin_caps))}\n"
                f"{time_line}"
            )

        # Check which of the requested caps are already granted in this chat
        existing = _get_chat_token(app, user_id, __chat_id__)
        if existing:
            already = existing.get("granted_caps", set())
            needed = requested - already
            if not needed:
                granted_list = ", ".join(sorted(already))
                return (
                    f"ALREADY_AUTHORIZED: This chat already has access to: {granted_list}. "
                    f"No additional authorization needed.\n"
                    f"{time_line}"
                )
        else:
            needed = requested

        url = _build_auth_url(
            app, self.valves, user_id, __chat_id__, email, needed)

        cap_desc = ", ".join(
            f"{c} ({CAPABILITIES[c][1]})" for c in sorted(needed))

        # ------------------------------------------------------------------
        # Event-based flow: modal dialog with clickable OAuth link,
        # blocks until user confirms, then verifies the token was cached.
        # ------------------------------------------------------------------
        if __event_call__:
            result = await __event_call__({
                "type": "confirmation",
                "data": {
                    "title": "Google Workspace Authorization Required",
                    "message": (
                        f'Right-click (or ⌘+click) the link below to open it in a new tab, complete the Google consent, then return here and click Confirm.\n\n'
                        f'<a href="{url}" rel="noopener" style="color: #4F46E5; font-weight: bold; text-decoration: underline;">Authorize Google Workspace access</a>\n\n'
                        f'Capabilities: {cap_desc}\n\n'
                        f'This grants access only for the current chat.'
                    ),
                },
            })

            if result:
                token = _get_chat_token(app, user_id, __chat_id__)
                if token and needed <= token.get("granted_caps", set()):
                    all_granted = ", ".join(sorted(token.get("granted_caps", set())))
                    return (
                        f"AUTHORIZED: {all_granted} granted.\n"
                        f"{time_line}"
                    )
                else:
                    return (
                        f"AUTH_INCOMPLETE: You confirmed but the token was not received. "
                        f"Please complete the Google consent screen first, then try again.\n"
                        f"{time_line}"
                    )
            else:
                return f"AUTH_CANCELLED: User cancelled authorization.\n{time_line}"

        # ------------------------------------------------------------------
        # Legacy fallback: return link in tool output for LLM to reproduce.
        # Used when __event_call__ is not available (API calls, etc.)
        # ------------------------------------------------------------------
        return (
            f"AUTH_REQUIRED: The user must click the link below to authorize.\n"
            f"IMPORTANT: You MUST reproduce this link EXACTLY in your reply — "
            f"the user cannot see tool outputs directly.\n\n"
            f"[Authorize Google Workspace access]({url})\n\n"
            f"Capabilities requested: {cap_desc}\n\n"
            f"This grants access only for the current chat.\n"
            f"{time_line}"
        )

    # -------------------------------------------------------------------
    # Tool: gws_action
    # -------------------------------------------------------------------

    async def gws_action(
        self,
        action: str,
        params: str = "{}",
        __user__: dict = {},
        __chat_id__: str = "",
        __request__=None,
    ) -> str:
        # docstring is set dynamically below
        if not __request__:
            return "ERROR: No request context."
        app = __request__.app
        _setup(app, self.valves)

        if not self.valves.google_client_id:
            return "ERROR: Tool not configured. Admin must set OAuth client ID and secret."

        if not __chat_id__:
            return "ERROR: No chat context available."

        # Resolve action
        action_entry = ACTIONS.get(action)
        if not action_entry:
            available = ", ".join(sorted(ACTIONS.keys()))
            return f"ERROR: Unknown action '{action}'. Available actions: {available}"

        required_cap, handler, action_desc = action_entry
        admin_caps = _parse_caps(self.valves.enabled_capabilities)

        # Gate 1: admin capability ceiling
        if required_cap not in admin_caps:
            return (
                f"NOT_ENABLED: The action '{action}' requires capability "
                f"'{required_cap}', which is not enabled by the admin. "
                f"Enabled capabilities: {', '.join(sorted(admin_caps))}"
            )

        user_id = __user__["id"]

        # Gate 2: per-chat authorization
        entry = _get_chat_token(app, user_id, __chat_id__)
        if not entry or required_cap not in entry.get("granted_caps", set()):
            # Also check if a broader scope covers it (e.g. 'drive' covers 'drive.readonly')
            granted = entry.get("granted_caps", set()) if entry else set()
            # Simple subsumption: 'X' subsumes 'X.readonly'
            base_cap = required_cap.replace(".readonly", "")
            has_broader = base_cap in granted and base_cap != required_cap

            if not has_broader:
                return (
                    f"AUTH_REQUIRED: This chat needs capability '{required_cap}' "
                    f"for action '{action}'. "
                    f"Call gws_authorize with capabilities='{required_cap}' first."
                )

        token = entry["access_token"]

        # Parse params
        try:
            parsed_params = json.loads(params) if isinstance(params, str) else params
        except json.JSONDecodeError as e:
            return f"ERROR: Invalid JSON in params: {e}"

        # Dispatch to handler
        try:
            return await handler(token, parsed_params, app, user_id, __chat_id__)
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {e}"

    # Set the docstring dynamically so it reflects the current action registry
    gws_action.__doc__ = _build_action_docs()
