"""
title: Google Workspace
author: Adam Smith
author_url: https://adamsmith.as
description: Per-user, per-chat OAuth2 access to Google Workspace APIs. Ephemeral tokens — every chat starts unauthorized. Admin valves control which capabilities are available.
required_open_webui_version: 0.4.0
version: 0.4.0
licence: MIT
requirements: httpx
"""

import hashlib
import httpx
import secrets
import time
import urllib.parse
from pydantic import BaseModel, Field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_ID = "gws_toolkit"
TOOL_VERSION = "0.4.0"
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
    "gmail.send": (
        "https://www.googleapis.com/auth/gmail.send",
        "Send email on behalf of the user",
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
# Each action maps to: (required_capability, handler_function_name, description)
# Handler functions are defined below and looked up by name at dispatch time.
# Action names mirror the Google API resource paths:
#   {service}.{resource}.{verb}
# ---------------------------------------------------------------------------

ACTIONS = {
    # --- Drive (readonly) ---
    "drive.files.search": (
        "drive.readonly",
        "_action_drive_search",
        "Search Drive for files matching a text query",
    ),
    "drive.files.get": (
        "drive.readonly",
        "_action_drive_read",
        "Read a Drive file by ID (exports Docs as markdown, Sheets as CSV, Slides as text)",
    ),
    "drive.files.list": (
        "drive.readonly",
        "_action_drive_list",
        "List files in a Drive folder",
    ),
    # Future actions go here.  Each entry automatically appears in the
    # gws_action docstring and is gated by its required capability.
}


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


def _token_cache(app) -> dict:
    """Per-chat token cache.  Lost on restart — by design."""
    key = f"__{TOOL_ID}_tokens__"
    c = getattr(app.state, key, None)
    if c is None:
        c = {}
        setattr(app.state, key, c)
    return c


def _pending_states(app) -> dict:
    """OAuth state -> {user_id, chat_id, requested_caps} for in-flight flows."""
    key = f"__{TOOL_ID}_pending__"
    s = getattr(app.state, key, None)
    if s is None:
        s = {}
        setattr(app.state, key, s)
    return s


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
    h = hashlib.sha256(
        f"{TOOL_VERSION}:{client_id}:{client_secret}:{base_url}".encode())
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
        requested_caps = flow["requested_caps"]

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
            f"<h2>Google Workspace access granted</h2>"
            f"<p>Capabilities: {cap_list}</p>"
            f"<p>This access is for the current chat only. "
            f"You can close this tab and return to the chat.</p>"
            f"<script>window.close()</script>")

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
        "requested_caps": requested_caps,
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
# Action handlers  (all receive token, params; return string)
# ---------------------------------------------------------------------------


async def _action_drive_search(token: str, params: dict, app, user_id, chat_id) -> str:
    """Search Drive for files matching a text query."""
    query = params.get("query", "")
    if not query:
        return "ERROR: 'query' parameter is required."

    safe_q = query.replace("\\", "\\\\").replace("'", "\\'")
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://www.googleapis.com/drive/v3/files",
            params={
                "q": f"fullText contains '{safe_q}' and trashed=false",
                "pageSize": 10,
                "fields": "files(id,name,mimeType,webViewLink,modifiedTime)",
                "orderBy": "modifiedTime desc",
            },
            headers={"Authorization": f"Bearer {token}"})

    if resp.status_code == 401:
        _clear_chat_token(app, user_id, chat_id)
        return "AUTH_EXPIRED: Token expired. The user must re-authorize for this chat."
    if resp.status_code != 200:
        return f"API_ERROR: {resp.status_code}: {resp.text[:300]}"

    files = resp.json().get("files", [])
    if not files:
        return f"NO_RESULTS: No files matching '{query}'."

    def fmt(f):
        m = f.get("mimeType", "")
        t = m.split(".")[-1] if "google-apps" in m else m.split("/")[-1]
        return (f"- {f.get('name','?')} | type={t} "
                f"| modified={f.get('modifiedTime','')[:10]} "
                f"| id={f.get('id','')} | link={f.get('webViewLink','')}")

    return f"RESULTS: {len(files)} file(s):\n" + "\n".join(fmt(f) for f in files)


async def _action_drive_read(token: str, params: dict, app, user_id, chat_id) -> str:
    """Read a Drive file by ID."""
    file_id = params.get("file_id", "")
    if not file_id:
        return "ERROR: 'file_id' parameter is required."

    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        meta_r = await client.get(
            f"https://www.googleapis.com/drive/v3/files/{file_id}",
            params={"fields": "id,name,mimeType,size"}, headers=headers)

        if meta_r.status_code == 401:
            _clear_chat_token(app, user_id, chat_id)
            return "AUTH_EXPIRED: Token expired. The user must re-authorize for this chat."
        if meta_r.status_code != 200:
            return f"API_ERROR: {meta_r.text[:300]}"

        meta = meta_r.json()
        name = meta.get("name", "Untitled")
        mime = meta.get("mimeType", "")

        export_map = {
            "application/vnd.google-apps.document": ("text/markdown", "md"),
            "application/vnd.google-apps.spreadsheet": ("text/csv", "csv"),
            "application/vnd.google-apps.presentation": ("text/plain", "txt"),
        }

        if mime in export_map:
            export_mime, ext = export_map[mime]
            resp = await client.get(
                f"https://www.googleapis.com/drive/v3/files/{file_id}/export",
                params={"mimeType": export_mime}, headers=headers)
        elif mime.startswith("text/") or mime == "application/json":
            resp = await client.get(
                f"https://www.googleapis.com/drive/v3/files/{file_id}",
                params={"alt": "media"}, headers=headers)
            ext = mime.split("/")[-1]
        elif mime == "application/pdf":
            return (f"FILE_INFO: '{name}' is a PDF (no text extraction). "
                    f"Link: https://drive.google.com/file/d/{file_id}/view")
        else:
            return (f"FILE_INFO: '{name}' ({mime}) cannot be read as text. "
                    f"Link: https://drive.google.com/file/d/{file_id}/view")

        if resp.status_code != 200:
            return f"API_ERROR: {resp.text[:300]}"

        content = resp.text[:16384]
        trunc = " (TRUNCATED)" if len(resp.text) > 16384 else ""
        return f"FILE_CONTENT: name='{name}'{trunc}\n\n{content}"


async def _action_drive_list(token: str, params: dict, app, user_id, chat_id) -> str:
    """List files in a Drive folder."""
    folder_id = params.get("folder_id", "root")

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://www.googleapis.com/drive/v3/files",
            params={
                "q": f"'{folder_id}' in parents and trashed=false",
                "pageSize": 50,
                "fields": "files(id,name,mimeType,modifiedTime)",
                "orderBy": "folder,name",
            },
            headers={"Authorization": f"Bearer {token}"})

    if resp.status_code == 401:
        _clear_chat_token(app, user_id, chat_id)
        return "AUTH_EXPIRED: Token expired. The user must re-authorize for this chat."
    if resp.status_code != 200:
        return f"API_ERROR: {resp.status_code}: {resp.text[:300]}"

    files = resp.json().get("files", [])
    if not files:
        return "EMPTY: Folder contains no items."

    def fmt(f):
        m = f.get("mimeType", "")
        k = "folder" if m == "application/vnd.google-apps.folder" else (
            m.split(".")[-1] if "google-apps" in m else m.split("/")[-1])
        return (f"- {f.get('name','?')} | type={k} "
                f"| modified={f.get('modifiedTime','')[:10]} | id={f.get('id','')}")

    return f"LISTING: {len(files)} item(s):\n" + "\n".join(fmt(f) for f in files)


# Handler lookup (module-level functions by name)
_ACTION_HANDLERS = {
    "_action_drive_search": _action_drive_search,
    "_action_drive_read": _action_drive_read,
    "_action_drive_list": _action_drive_list,
}


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
        self.citation = True

    # -------------------------------------------------------------------
    # Tool: gws_authorize
    # -------------------------------------------------------------------

    async def gws_authorize(
        self,
        capabilities: str = "",
        __user__: dict = {},
        __chat_id__: str = "",
        __request__=None,
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
            return "\n".join(lines)

        disallowed = requested - admin_caps
        if disallowed:
            return (
                f"NOT_ENABLED: Capability {', '.join(sorted(disallowed))} "
                f"not enabled by admin. "
                f"Admin-enabled capabilities: {', '.join(sorted(admin_caps))}"
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
                    f"No additional authorization needed."
                )
        else:
            needed = requested

        url = _build_auth_url(
            app, self.valves, user_id, __chat_id__, email, needed)

        cap_desc = ", ".join(
            f"{c} ({CAPABILITIES[c][1]})" for c in sorted(needed))
        return (
            f"AUTH_REQUIRED: The user must open this URL to grant access for "
            f"this chat session:\n\n{url}\n\n"
            f"Capabilities requested: {cap_desc}\n\n"
            f"This grants access only for the current chat. "
            f"The user can revoke it at any time from "
            f"https://myaccount.google.com/permissions"
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

        required_cap, handler_name, action_desc = action_entry
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
        import json as _json
        try:
            parsed_params = _json.loads(params) if isinstance(params, str) else params
        except _json.JSONDecodeError as e:
            return f"ERROR: Invalid JSON in params: {e}"

        # Dispatch to handler
        handler = _ACTION_HANDLERS.get(handler_name)
        if not handler:
            return f"ERROR: Handler '{handler_name}' not found (internal error)."

        try:
            return await handler(token, parsed_params, app, user_id, __chat_id__)
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {e}"

    # Set the docstring dynamically so it reflects the current action registry
    gws_action.__doc__ = _build_action_docs()
