"""Optional OWUI ASGI entrypoint for distributed Google Workspace callbacks.

Run uvicorn owui_worker:create_app --factory instead of open_webui.main:app, with this directory
on PYTHONPATH. This thin adapter is version-sensitive: qualify it on your OWUI
release. The toolkit itself still uploads as a single file.
"""

import sys

from fastapi import Request
from fastapi.responses import HTMLResponse

CALLBACK_PATH = "/api/v1/x/gws_toolkit/oauth/callback"


class CallbackApp:
    """Intercept only the callback before OWUI's SPA, even on an untouched worker.

Forward lifespan, WebSockets and every other route unmodified. Resolve toolkit
source and valves from OWUI's database per callback, respecting edits/reloads.
No secrets are copied into adapter config or imported from environment files.
"""

    def __init__(self, core, resolve):
        self.core = core
        self.resolve = resolve

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != CALLBACK_PATH:
            return await self.core(scope, receive, send)
        if scope["method"] != "GET":
            response = HTMLResponse("Method not allowed", status_code=405, headers={"Allow": "GET"})
        else:
            request = Request({**scope, "app": self.core}, receive=receive)
            try:
                module, valves = await self.resolve(request)
                if not valves.google_client_id or not valves.google_client_secret:
                    response = HTMLResponse("Authorization not configured", status_code=503)
                else:
                    module._setup(self.core, valves)
                    # Use the just-resolved module, not a prior route closure
                    # left behind by a same-version source reload.
                    endpoint = module._callback_endpoint(
                        valves.google_client_id, valves.google_client_secret, valves.base_url)
                    response = await endpoint(request)
            except Exception:
                # Never expose database exceptions, credentials or callback URLs.
                response = HTMLResponse("Authorization unavailable. Please retry later.", status_code=503)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return await response(scope, receive, send)


def create_app():
    from open_webui.main import app as core
    from open_webui.models.tools import Tools
    from open_webui.utils.plugin import get_tool_module_from_cache

    async def resolve(request):
        tool, _ = await get_tool_module_from_cache(request, "gws_toolkit")
        values = await Tools.get_tool_valves_by_id("gws_toolkit") or {}
        return sys.modules[type(tool).__module__], tool.Valves(**values)

    return CallbackApp(core, resolve)


# Use `uvicorn owui_worker:create_app --factory ...` so tests can import the
# wrapper without importing OWUI or initializing its database.
