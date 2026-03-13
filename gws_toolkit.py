"""
title: Google Workspace
author: Adam Smith
author_url: https://adamsmith.as
description: Per-user OAuth2 access to Google Drive (read-only). Self-registers an OAuth callback endpoint.
required_open_webui_version: 0.4.0
version: 0.3.3
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
TOOL_VERSION = "0.3.3"
ROUTE_PREFIX = f"/api/v1/x/{TOOL_ID}"
CALLBACK_PATH = f"{ROUTE_PREFIX}/oauth/callback"

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
DEFAULT_SCOPES = "https://www.googleapis.com/auth/drive.readonly"


# ---------------------------------------------------------------------------
# Route helpers (see: https://gist.github.com/rndmcnlly/740a0238962de750c5fd14e606fe8c90)
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
# Token persistence (UserValves via OWUI DB) + in-process cache
# ---------------------------------------------------------------------------


def _db_save(user_id: str, refresh_token: str):
    """Persist refresh token to user settings in OWUI's DB (invisible, no UI)."""
    try:
        from open_webui.models.tools import Tools as DB
        DB.update_user_valves_by_id_and_user_id(
            id=TOOL_ID, user_id=user_id,
            valves={"_rt": refresh_token},
        )
    except Exception:
        pass


def _db_load(user_id: str) -> Optional[str]:
    """Load refresh token from UserValves."""
    try:
        from open_webui.models.tools import Tools as DB
        v = DB.get_user_valves_by_id_and_user_id(TOOL_ID, user_id)
        return v.get("_rt") if v else None
    except Exception:
        return None


def _db_clear(user_id: str):
    """Clear stored refresh token."""
    try:
        from open_webui.models.tools import Tools as DB
        DB.update_user_valves_by_id_and_user_id(
            id=TOOL_ID, user_id=user_id,
            valves={"_rt": ""},
        )
    except Exception:
        pass


def _cache(app) -> dict:
    """In-process token cache (lost on restart, fast between calls)."""
    key = f"__{TOOL_ID}_cache__"
    c = getattr(app.state, key, None)
    if c is None:
        c = {}
        setattr(app.state, key, c)
    return c


def _pending_states(app) -> dict:
    """OAuth state -> user_id mapping for in-flight auth flows."""
    key = f"__{TOOL_ID}_pending__"
    s = getattr(app.state, key, None)
    if s is None:
        s = {}
        setattr(app.state, key, s)
    return s


# ---------------------------------------------------------------------------
# Route registration (version-stamped, idempotent)
# ---------------------------------------------------------------------------


def _routes_version(client_id: str, client_secret: str, base_url: str) -> str:
    """Compute a version stamp from code version + valve values."""
    h = hashlib.sha256(f"{TOOL_VERSION}:{client_id}:{client_secret}:{base_url}".encode())
    return h.hexdigest()[:12]


def _ensure_routes(app, client_id: str, client_secret: str, base_url: str):
    """Register the OAuth callback. Skips if already current."""
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
        user_id = pending.pop(state, None)
        if not user_id:
            return HTMLResponse(
                "<h2>Expired or invalid state</h2>"
                "<p>Please start the authorization flow again from the chat.</p>",
                status_code=400)

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
        refresh = td.get("refresh_token", "")
        access = td.get("access_token", "")
        scope = td.get("scope", "")
        expires_at = time.time() + td.get("expires_in", 3600) - 60

        if refresh:
            _db_save(user_id, refresh)

        _cache(request.app)[user_id] = {
            "refresh_token": refresh,
            "access_token": access,
            "expires_at": expires_at,
        }

        return HTMLResponse(
            "<h2>Connected to Google Workspace</h2>"
            "<p>You can close this tab and return to the chat.</p>"
            "<script>window.close()</script>")

    _insert_route_before_spa(app, CALLBACK_PATH, oauth_callback, methods=["GET"])
    setattr(app.state, version_key, target)


# ---------------------------------------------------------------------------
# Token resolution
# ---------------------------------------------------------------------------


async def _get_token(app, user_id: str, client_id: str, client_secret: str) -> Optional[str]:
    """
    Return a valid access token. Checks cache, then DB, refreshes if needed.
    Returns None if user has never connected.
    """
    c = _cache(app)
    entry = c.get(user_id)

    if not entry or not entry.get("refresh_token"):
        rt = _db_load(user_id)
        if not rt:
            return None
        entry = {"refresh_token": rt, "access_token": None, "expires_at": 0}
        c[user_id] = entry

    if entry.get("access_token") and entry.get("expires_at", 0) > time.time():
        return entry["access_token"]

    async with httpx.AsyncClient() as client:
        resp = await client.post(GOOGLE_TOKEN_URL, data={
            "refresh_token": entry["refresh_token"],
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
        })

    if resp.status_code != 200:
        return None

    d = resp.json()
    entry["access_token"] = d["access_token"]
    entry["expires_at"] = time.time() + d.get("expires_in", 3600) - 60
    if "refresh_token" in d:
        entry["refresh_token"] = d["refresh_token"]
        _db_save(user_id, d["refresh_token"])
    return entry["access_token"]


def _clear_tokens(app, user_id: str):
    _cache(app).pop(user_id, None)
    _db_clear(user_id)


# ---------------------------------------------------------------------------
# Tool preamble helpers (module-level so OWUI doesn't expose them as tools)
# ---------------------------------------------------------------------------


def _setup(app, valves):
    """Lazy route registration, called once per tool invocation."""
    if valves.google_client_id and valves.google_client_secret:
        _ensure_routes(
            app, valves.google_client_id,
            valves.google_client_secret, valves.base_url)


async def _authed(valves, __user__, __request__) -> tuple:
    """
    Common preamble: ensure routes, resolve token.
    Returns (app, user_id, token_or_none).
    """
    app = __request__.app
    _setup(app, valves)
    user_id = __user__["id"]
    token = await _get_token(
        app, user_id,
        valves.google_client_id, valves.google_client_secret)
    return app, user_id, token


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

    def __init__(self):
        self.valves = self.Valves()
        self.citation = True

    # -------------------------------------------------------------------
    # Tool methods
    # -------------------------------------------------------------------

    async def connect_google_workspace(
        self, __user__: dict, __request__=None,
    ) -> str:
        """
        Connect the user's Google account to enable Drive access.
        Call this when a user wants to link Google Workspace or when another
        tool method reports NOT_CONNECTED.
        """
        if not __request__:
            return "ERROR: No request context."

        app, user_id, token = await _authed(self.valves, __user__, __request__)

        if not self.valves.google_client_id:
            return "ERROR: Tool not configured. Admin must set OAuth client ID and secret."

        if token:
            return "ALREADY_CONNECTED: User has a valid Google Workspace connection."

        state = secrets.token_urlsafe(32)
        _pending_states(app)[state] = user_id

        params = {
            "client_id": self.valves.google_client_id,
            "redirect_uri": self.valves.base_url.rstrip("/") + CALLBACK_PATH,
            "response_type": "code",
            "scope": DEFAULT_SCOPES,
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
        email = __user__.get("email", "")
        if email:
            params["login_hint"] = email

        url = GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)
        return (
            f"AUTH_REQUIRED: The user must open this URL in their browser to "
            f"connect their Google account, then retry their request. URL: {url} "
            f"Also let the user know: this grants read-only access to their Drive. "
            f"They can revoke it at any time from https://myaccount.google.com/permissions")

    async def search_drive(
        self, query: str, __user__: dict, __request__=None,
    ) -> str:
        """
        Search the user's Google Drive for files matching a text query.
        :param query: Search terms (e.g. 'budget 2025', 'syllabus')
        """
        if not __request__:
            return "ERROR: No request context."

        app, user_id, token = await _authed(self.valves, __user__, __request__)
        if not token:
            return "NOT_CONNECTED: Call connect_google_workspace first."

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
            _clear_tokens(app, user_id)
            return "AUTH_EXPIRED: Call connect_google_workspace to reconnect."
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

    async def read_drive_file(
        self, file_id: str, __user__: dict, __request__=None,
    ) -> str:
        """
        Read a Google Drive file by ID. Exports Docs as markdown, Sheets as CSV, Slides as text.
        :param file_id: The file ID (from search results or a Drive URL)
        """
        if not __request__:
            return "ERROR: No request context."

        app, user_id, token = await _authed(self.valves, __user__, __request__)
        if not token:
            return "NOT_CONNECTED: Call connect_google_workspace first."

        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient() as client:
            meta_r = await client.get(
                f"https://www.googleapis.com/drive/v3/files/{file_id}",
                params={"fields": "id,name,mimeType,size"}, headers=headers)

            if meta_r.status_code == 401:
                _clear_tokens(app, user_id)
                return "AUTH_EXPIRED: Call connect_google_workspace to reconnect."
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

    async def list_drive_folder(
        self, folder_id: str = "root", __user__: dict = {}, __request__=None,
    ) -> str:
        """
        List files in a Google Drive folder.
        :param folder_id: Folder ID, or 'root' for the top level (default: root)
        """
        if not __request__:
            return "ERROR: No request context."

        app, user_id, token = await _authed(self.valves, __user__, __request__)
        if not token:
            return "NOT_CONNECTED: Call connect_google_workspace first."

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
            _clear_tokens(app, user_id)
            return "AUTH_EXPIRED: Call connect_google_workspace to reconnect."
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

    async def disconnect_google_workspace(
        self, __user__: dict, __request__=None,
    ) -> str:
        """
        Disconnect the user's Google account. Revokes tokens.
        """
        if not __request__:
            return "ERROR: No request context."

        app = __request__.app
        user_id = __user__["id"]

        entry = _cache(app).get(user_id)
        if entry and entry.get("access_token"):
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(
                        "https://oauth2.googleapis.com/revoke",
                        params={"token": entry["access_token"]})
            except Exception:
                pass

        _clear_tokens(app, user_id)
        return (
            "DISCONNECTED: Tokens removed from this service. "
            "Inform the user that they can also independently revoke access from "
            "Google's side at https://myaccount.google.com/permissions")
