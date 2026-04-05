# 🐙 Google Workspace Toolkit for Open WebUI

Open WebUI tool that gives LLMs authenticated, per-user, per-chat access to Google Workspace APIs through native function calling. Each user authorizes with their own Google account via OAuth2 — no service accounts, no shared credentials. Tokens are ephemeral: every chat starts unauthorized, and access is scoped to exactly the capabilities needed.

**22 actions across 4 services. Reads and writes.** The octopus can search your Drive, read your email, draft replies, create and reschedule calendar events, and read/write spreadsheet data — all gated by admin capability ceilings and per-chat user consent.

## What it does

- **`gws_authorize`** — request authorization for specific capabilities in the current chat, or call with no arguments to inspect what's granted. Also returns the current server time (UTC) to ground the LLM's sense of "now."
- **`gws_action`** — execute Google Workspace actions across Drive, Gmail, Calendar, and Sheets, gated by both admin-enabled capabilities and per-chat user authorization

Admin valves set a capability ceiling. Users can only authorize up to the admin-allowed maximum, and must re-consent in each new chat.

## Architecture

```
User in chat ──► LLM calls gws_action ──► Dispatcher checks:
                                            1. Is this action's capability admin-enabled?
                                            2. Does this chat have a token with that capability?
                              ┌──────────── both yes ────────────┐
                              │                                   │
                              │ no                                ▼
                              ▼                          Call Google API,
                   Return AUTH_REQUIRED                  return results
                   LLM calls gws_authorize
                              │
                              ▼
                   Return consent URL to user
                   User clicks ──► Google consent ──► callback endpoint
                              │
                              ▼
                   Exchange code for access token
                   Store in per-chat in-memory cache
                   User retries request
```

Key properties:
- **Ephemeral tokens.** No database persistence, no refresh tokens. Tokens live in-process memory keyed by `(user_id, chat_id)` and are lost on server restart. This is by design.
- **Per-chat authorization.** Each chat starts with no access. Users consent to exactly what's needed for that conversation.
- **Incremental auth.** If a chat needs Drive first and Calendar later, the user consents to each separately. Google's `include_granted_scopes` merges them into one token.
- **Admin capability ceiling.** The `enabled_capabilities` valve determines what's possible. Users can never exceed it.
- **Time grounding.** Every `gws_authorize` response includes the current server time in UTC, so the LLM knows what "today" means before constructing time-relative API parameters.

The callback endpoint is injected into OWUI's FastAPI routing table before the SPA catch-all mount. See the [route registration pattern](https://gist.github.com/rndmcnlly/740a0238962de750c5fd14e606fe8c90) for details.

## Capabilities

Capability names mirror Google's OAuth scope suffixes. Admins and users see the same names Google uses.

| Capability | Google Scope | Description |
|---|---|---|
| `drive.readonly` | `drive.readonly` | Search, read, list Drive files |
| `drive` | `drive` | Full Drive access |
| `gmail.readonly` | `gmail.readonly` | Read Gmail messages and drafts |
| `gmail.compose` | `gmail.compose` | Create and manage email drafts |
| `calendar.readonly` | `calendar.readonly` | View calendar events |
| `calendar.events` | `calendar.events` | Create, edit, and delete events |
| `spreadsheets.readonly` | `spreadsheets.readonly` | Read Sheets data |
| `spreadsheets` | `spreadsheets` | Read and write Sheets |
| `tasks.readonly` | `tasks.readonly` | View Google Tasks |
| `tasks` | `tasks` | Manage Google Tasks |
| `documents.readonly` | `documents.readonly` | Read Docs content |
| `documents` | `documents` | Read and write Docs |
| `presentations.readonly` | `presentations.readonly` | Read Slides content |
| `presentations` | `presentations` | Read and write Slides |

Drive, Gmail, Calendar, and Sheets have action handlers. Tasks, Docs, and Slides are scope-ready in the capability registry but have no handlers yet.

## Actions

### Drive (readonly)

| Action | Capability | Description |
|---|---|---|
| `drive.files.search` | `drive.readonly` | Full-text search across Drive |
| `drive.files.get` | `drive.readonly` | Read a file (exports Docs as markdown, Sheets as CSV, Slides as text) |
| `drive.files.list` | `drive.readonly` | List folder contents |

### Gmail (read + compose)

| Action | Capability | Description |
|---|---|---|
| `gmail.messages.search` | `gmail.readonly` | Search messages using Gmail search syntax |
| `gmail.messages.get` | `gmail.readonly` | Read a message (decodes MIME body to text) |
| `gmail.threads.list` | `gmail.readonly` | Search threads |
| `gmail.threads.get` | `gmail.readonly` | Read all messages in a thread |
| `gmail.drafts.create` | `gmail.compose` | Create a draft (does NOT send) |
| `gmail.drafts.list` | `gmail.readonly` | List drafts |
| `gmail.drafts.get` | `gmail.readonly` | Read a specific draft |

The `gmail.compose` scope can technically send email, but we don't implement a send handler. The safety guarantee is architectural — the octopus reaches into the drafts folder; the human clicks Send.

### Calendar (read + write)

| Action | Capability | Description |
|---|---|---|
| `calendar.calendars.list` | `calendar.readonly` | List available calendars |
| `calendar.events.list` | `calendar.readonly` | List/search events (defaults to upcoming) |
| `calendar.events.get` | `calendar.readonly` | Full event details |
| `calendar.freebusy.query` | `calendar.readonly` | Check free/busy status for a time range |
| `calendar.events.create` | `calendar.events` | Create an event |
| `calendar.events.patch` | `calendar.events` | Update specific fields of an event |
| `calendar.events.delete` | `calendar.events` | Delete an event |

Write actions default `sendUpdates` to `"none"` — the LLM won't silently send invite emails unless it explicitly passes `"all"`.

### Sheets (read + write)

| Action | Capability | Description |
|---|---|---|
| `sheets.spreadsheets.get` | `spreadsheets.readonly` | Spreadsheet metadata: sheet names, dimensions, named ranges |
| `sheets.values.get` | `spreadsheets.readonly` | Read a cell range (e.g. `Sheet1!A1:D20`) |
| `sheets.values.batchGet` | `spreadsheets.readonly` | Read multiple cell ranges in one call |
| `sheets.values.update` | `spreadsheets` | Write values to a cell range (overwrites) |
| `sheets.values.append` | `spreadsheets` | Append rows after the last row of a detected table |

Write actions default `valueInputOption` to `"USER_ENTERED"` (formulas and dates are interpreted). Append defaults `insertDataOption` to `"INSERT_ROWS"` (won't clobber data below the table).

## Admin setup

### 1. Create an OAuth client

In your GCP project, create an **OAuth 2.0 Client ID** of type **Web application**.

Add this as an authorized redirect URI:

```
https://<your-owui-host>/api/v1/x/gws_toolkit/oauth/callback
```

### 2. Configure the OAuth consent screen

Set the consent screen to **Internal** if all users are on your Google Workspace domain. Otherwise use **External** with test users.

### 3. Enable the relevant APIs

Enable the Google APIs matching your enabled capabilities in the same GCP project:

- **Google Drive API** for `drive.readonly` / `drive`
- **Gmail API** for `gmail.readonly` / `gmail.compose`
- **Google Calendar API** for `calendar.readonly` / `calendar.events`
- **Google Sheets API** for `spreadsheets.readonly` / `spreadsheets`

APIs that aren't enabled will return a 403 with a direct link to the GCP console to enable them.

### 4. Install the tool

Upload `gws_toolkit.py` as a new tool in Open WebUI (Workspace > Tools), or push it via the API.

### 5. Set the admin Valves

| Valve | Value |
|-------|-------|
| `google_client_id` | Your OAuth Web Application client ID |
| `google_client_secret` | Your OAuth Web Application client secret |
| `base_url` | Public URL of your OWUI instance (e.g. `https://chat.example.com`) |
| `enabled_capabilities` | Comma-separated capability ceiling (e.g. `drive.readonly,calendar.readonly`) |

The default `enabled_capabilities` is `drive.readonly` only. Enable additional capabilities as needed.

The `base_url` must match the redirect URI origin configured in step 1.

### 6. Enable the tool on a model

In Workspace > Models, enable "Google Workspace" for any model that supports native function calling.

## User experience

1. User asks something that needs Drive access (e.g. "find my budget spreadsheet")
2. LLM calls `gws_action(action="drive.files.search", ...)`, gets `AUTH_REQUIRED`
3. LLM calls `gws_authorize(capabilities="drive.readonly")`, gets a consent URL
4. LLM presents the link in its reply, user clicks it, authorizes in a new tab
5. Tab closes automatically, user retries their request
6. Subsequent Drive requests in this chat work without re-authorization
7. New chat → starts fresh, requires new consent

Power users can add a system prompt instruction to call `gws_authorize` up front with their preferred capability set.

## Limitations

- **~1 hour token lifetime.** Access tokens from `access_type=online` expire in about an hour. For long chats, the LLM will see `AUTH_EXPIRED` and re-trigger authorization. This is consistent with the per-chat consent model.
- **Orphaned routes on tool deletion.** OWUI has no `on_delete` hook, so the callback route persists until server restart.
- **Single tool ID.** The callback route path is derived from a hardcoded `TOOL_ID`. Deploying two copies of the toolkit under different OWUI tool IDs will cause route collisions. Only one instance should exist per OWUI deployment.
- **No send.** Gmail drafts can be created but not sent. This is deliberate.

## Files

- `gws_toolkit.py` — the tool (single file, deploy as-is)
