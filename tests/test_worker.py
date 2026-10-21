"""Callback adapter contract without importing or installing Open WebUI."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from owui_worker import CALLBACK_PATH, CallbackApp


class WorkerAdapter(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.core = FastAPI()
        self.calls = 0
        self.version = "first"

        async def endpoint(request):
            return HTMLResponse(self.version)

        def setup(app, valves):
            if not any(getattr(r, "path", None) == CALLBACK_PATH for r in app.router.routes):
                app.add_api_route(CALLBACK_PATH, endpoint)

        async def resolve(request):
            self.calls += 1
            snapshot = self.version

            async def current_endpoint(request):
                return HTMLResponse(snapshot)

            return SimpleNamespace(_setup=setup, _callback_endpoint=lambda *args: current_endpoint), SimpleNamespace(
                google_client_id="synthetic", google_client_secret="synthetic", base_url="http://test")

        self.wrapper = CallbackApp(self.core, resolve)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.wrapper), base_url="http://test")

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_cold_callback_loads_without_any_prior_tool_call(self):
        self.assertFalse(any(getattr(r, "path", None) == CALLBACK_PATH for r in self.core.router.routes))
        response = await self.client.get(CALLBACK_PATH)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls, 1)
        self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_resolves_again_after_configuration_change(self):
        await self.client.get(CALLBACK_PATH)
        self.version = "second"
        response = await self.client.get(CALLBACK_PATH)
        self.assertEqual(response.text, "second")
        self.assertEqual(self.calls, 2)

    async def test_other_routes_bypass_resolver(self):
        response = await self.client.get("/not-found")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.calls, 0)

    async def test_wrong_method_rejected(self):
        self.assertEqual((await self.client.post(CALLBACK_PATH)).status_code, 405)
        self.assertEqual(self.calls, 0)

    async def test_resolver_failure_is_content_free(self):
        async def broken(request):
            raise RuntimeError("secret=synthetic-do-not-echo")
        self.wrapper.resolve = broken
        response = await self.client.get(CALLBACK_PATH)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("secret", response.text)

    async def test_lifespan_and_websocket_are_forwarded(self):
        seen = []

        async def core(scope, receive, send):
            seen.append(scope["type"])

        wrapper = CallbackApp(core, self.wrapper.resolve)
        for kind in ("lifespan", "websocket"):
            await wrapper({"type": kind}, None, None)
        self.assertEqual(seen, ["lifespan", "websocket"])
        self.assertEqual(self.calls, 0)


if __name__ == "__main__":
    unittest.main()
