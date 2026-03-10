# Google Workspace Toolkit for Open WebUI

Proof-of-concept Open WebUI tool that gives users read-only access to their Google Drive through native function calling. Each user authorizes with their own Google account via OAuth2 -- no service accounts, no shared credentials. User refresh tokens are stored in OWUI's database; admins with DB access can read them.

## What it does

- **`connect_google_workspace`** -- generates a per-user OAuth2 authorization link
- **`search_drive`** -- full-text search across the user's Drive
- **`read_drive_file`** -- reads Docs (as markdown), Sheets (as CSV), Slides (as text), and plain text files
- **`list_drive_folder`** -- lists folder contents
- **`disconnect_google_workspace`** -- revokes tokens and clears stored credentials

The tool self-registers an OAuth callback endpoint on the OWUI FastAPI app at runtime. Refresh tokens are persisted to OWUI's database per-user, so authorization survives server restarts. Access tokens are cached in-process for performance.

## Architecture

```
User in chat ──► LLM calls tool method ──► Tool checks for stored token
                                              │
                              ┌────────────── has token? ──────────────┐
                              │ no                                     │ yes
                              ▼                                        ▼
                   return auth URL to LLM              refresh if needed, call
                   LLM presents link to user           Google Drive REST API
                              │
                              ▼
                   User clicks link ──► Google consent ──► callback endpoint
                              │
                              ▼
                   Exchange code for tokens, persist refresh token to DB
```

The callback endpoint is injected into OWUI's FastAPI routing table before the SPA catch-all mount. See the [route registration pattern](https://gist.github.com/rndmcnlly/740a0238962de750c5fd14e606fe8c90) for details on why this is necessary.

## Admin setup

### 1. Create an OAuth client

In your GCP project, create an **OAuth 2.0 Client ID** of type **Web application**.

Add this as an authorized redirect URI:

```
https://<your-owui-host>/api/v1/x/gws_toolkit/oauth/callback
```

### 2. Configure the OAuth consent screen

Set the consent screen to **Internal** if all users are on your Google Workspace domain. Otherwise use **External** with test users.

No sensitive or restricted scope verification is needed for `drive.readonly` on Internal apps.

### 3. Enable the Drive API

Ensure the **Google Drive API** is enabled in the same GCP project.

### 4. Install the tool

Upload `gws_toolkit.py` as a new tool in Open WebUI (Workspace > Tools), or push it via the API.

### 5. Set the admin Valves

| Valve | Value |
|-------|-------|
| `google_client_id` | Your OAuth Web Application client ID |
| `google_client_secret` | Your OAuth Web Application client secret |
| `base_url` | Public URL of your OWUI instance (e.g. `https://chat.example.com`) |

The `base_url` must match what you configured as the redirect URI origin in step 1.

### 6. Enable the tool on a model

In Workspace > Models, enable "Google Workspace" for any model that supports native function calling.

## User experience

1. User asks something that needs Drive access (e.g. "find my budget spreadsheet")
2. LLM calls `search_drive`, tool returns `NOT_CONNECTED`
3. LLM calls `connect_google_workspace`, tool returns an auth URL
4. LLM presents the link, user clicks it, authorizes in a new tab
5. Tab closes automatically, user retries their request
6. Subsequent requests work without re-authorization

## Limitations

- **Drive read-only.** This is a deliberate scope constraint for the PoC. Adding Gmail, Calendar, Sheets write, etc. is straightforward (more scopes + more tool methods).
- **Tokens are in-process cached.** Access tokens live in `app.state` and are lost on OWUI restart. Refresh tokens persist in the DB, so users don't need to re-authorize -- but the first request after a restart incurs a token refresh round-trip.
- **Orphaned routes on tool deletion.** OWUI has no `on_delete` hook, so the callback route persists in the routing table until the next server restart. Harmless but worth knowing.
- **Single-page export for Sheets.** `read_drive_file` exports the first sheet as CSV. Multi-sheet spreadsheets need the Sheets API for full access.

## Files

- `gws_toolkit.py` -- the tool (single file, deploy as-is)

## See also

- [Google Workspace CLI](https://github.com/googleworkspace/cli) -- the `gws` CLI that inspired this tool's API surface. Useful for local prototyping against the same Google APIs.
