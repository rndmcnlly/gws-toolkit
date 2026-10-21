# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx==0.28.1", "fastapi==0.119.0", "beautifulsoup4==4.14.2", "html5lib==1.1", "redis==6.4.0"]
# ///
"""Offline memory tests; add REDIS_URL for the identical real-Redis contract.

uv run tests/test_state.py
REDIS_URL=redis://... uv run tests/test_state.py
Only UUID-namespaced synthetic keys are used. Never FLUSHDB.
"""

import asyncio
import inspect
import os
import sys
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit
from unittest.mock import patch

import httpx
from fastapi import FastAPI, Request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    import gws_toolkit as gws
except ModuleNotFoundError:
    import gws  # BayLeaf adapter mounts the same source under this module name.


class StateContract:
    async def asyncSetUp(self):
        self.app = FastAPI()
        self.app.state.redis = None
        self.tools = gws.Tools()
        self.tools.valves.google_client_id = "test-" + uuid.uuid4().hex
        self.tools.valves.google_client_secret = "synthetic-secret"
        self.tools.valves.base_url = "http://test"
        self.tools.valves.enabled_capabilities = "calendar.readonly,drive.readonly"
        gws._setup(self.app, self.tools.valves)
        self.cleanup_pattern = gws._state_key(self.app, "token", "u", "c").rsplit(":", 2)[0] + ":*"
        self.other = self.app
        self.clients = []

    async def asyncTearDown(self):
        for client in self.clients:
            # Remove only this test's configuration namespace, never all keys.
            async for key in client.scan_iter(match=self.cleanup_pattern):
                await client.delete(key)
            await client.aclose()

    async def begin(self, app=None, user="u", chat="c", caps=None):
        url = await gws._build_auth_url(app or self.app, self.tools.valves, user, chat, "", caps or {"calendar.readonly"})
        return parse_qs(urlsplit(url).query)

    async def save(self, token="synthetic", caps=None, lifetime=60):
        nonce = (await self.begin())["state"][0]
        flow = await gws._pop_pending(self.app, nonce)
        await gws._put_token(self.app, "u", "c", {
            "access_token": token, "granted_caps": caps or {"calendar.readonly"},
            "expires_at": time.time() + lifetime,
        }, nonce)
        await gws._finish_pending(self.app, nonce, flow)

    async def complete(self, nonce, response=None, error=None):
        query = {"state": nonce, "error": error} if error else {"state": nonce, "code": "synthetic-code"}
        request = Request({"type": "http", "app": self.other, "query_string": urlencode(query).encode(), "headers": []})
        result = response or {"access_token": "new", "expires_in": 3600,
                              "scope": "https://www.googleapis.com/auth/calendar.readonly"}
        transport = httpx.MockTransport(lambda req: httpx.Response(200, json=result))
        real_client = httpx.AsyncClient
        with patch.object(gws.httpx, "AsyncClient", lambda **kw: real_client(transport=transport, **kw)):
            return await gws._complete_authorization(request, "synthetic", "synthetic", "http://test/callback")

    async def test_nonce_once_and_flow_serialization(self):
        nonce = (await self.begin())["state"][0]
        with self.assertRaises(gws._AuthorizationPending):
            await self.begin(app=self.other)
        flow = await gws._pop_pending(self.other, nonce)
        self.assertEqual(flow, {"user_id": "u", "chat_id": "c"})
        self.assertIsNone(await gws._pop_pending(self.app, nonce))
        # Consuming the nonce does not unlock during the external token exchange.
        with self.assertRaises(gws._AuthorizationPending):
            await self.begin()
        await gws._finish_pending(self.other, nonce, flow)
        self.assertIn("state", await self.begin())

    async def test_token_visibility_isolation_and_revocation(self):
        await self.save()
        self.assertIsNotNone(await gws._get_chat_token(self.other, "u", "c"))
        self.assertIsNone(await gws._get_chat_token(self.other, "other", "c"))
        self.assertIsNone(await gws._get_chat_token(self.other, "u", "other"))
        await gws._clear_chat_token(self.other, "u", "c")
        self.assertIsNone(await gws._get_chat_token(self.app, "u", "c"))

    async def test_old_401_does_not_clear_new_token(self):
        await self.save(token="old")
        await self.save(token="new")
        await gws._clear_chat_token(self.other, "u", "c", "old")
        self.assertEqual((await gws._get_chat_token(self.app, "u", "c"))["access_token"], "new")
        await gws._clear_chat_token(self.other, "u", "c", "new")
        self.assertIsNone(await gws._get_chat_token(self.app, "u", "c"))

    async def test_token_expiry(self):
        await self.save(lifetime=0.08)
        await asyncio.sleep(0.15)
        self.assertIsNone(await gws._get_chat_token(self.other, "u", "c"))

    async def test_nonce_expiry_releases_chat(self):
        with patch.object(gws, "PENDING_TTL", 1):
            nonce = (await self.begin())["state"][0]
        await asyncio.sleep(1.1)
        self.assertIsNone(await gws._pop_pending(self.other, nonce))
        self.assertIn("state", await self.begin(app=self.other))

    async def test_stale_flow_cannot_write_or_release_new_flow(self):
        nonce = (await self.begin())["state"][0]
        flow = await gws._pop_pending(self.app, nonce)
        await gws._finish_pending(self.app, nonce, flow)
        new = (await self.begin())["state"][0]
        with self.assertRaises(gws._StateUnavailable):
            await gws._put_token(self.app, "u", "c", {
                "access_token": "stale", "expires_at": time.time() + 60,
                "granted_caps": set()}, nonce)
        await gws._finish_pending(self.app, nonce, flow)
        with self.assertRaises(gws._AuthorizationPending):
            await self.begin()
        self.assertIsNotNone(await gws._pop_pending(self.other, new))

    async def test_incremental_request_but_no_invented_grants(self):
        await self.save(caps={"drive.readonly"})
        params = await self.begin()
        self.assertEqual(gws._caps_from_scopes(params["scope"][0]), {"drive.readonly", "calendar.readonly"})
        self.assertEqual(params["include_granted_scopes"], ["true"])
        result = await self.complete(params["state"][0])
        self.assertEqual(result, {"calendar.readonly"})
        token = await gws._get_chat_token(self.other, "u", "c")
        self.assertEqual(token["granted_caps"], {"calendar.readonly"})

    async def test_denial_consumes_state_and_releases_chat(self):
        nonce = (await self.begin())["state"][0]
        self.assertEqual((await self.complete(nonce, error="access_denied")).status_code, 400)
        self.assertIsNone(await gws._pop_pending(self.app, nonce))
        self.assertIn("state", await self.begin())

    async def test_invalid_exchange_releases_chat(self):
        for value in ({"access_token": ""}, {"access_token": "x", "expires_in": -1},
                      {"access_token": "x", "expires_in": "nan"}, {"access_token": "x", "scope": []}):
            nonce = (await self.begin())["state"][0]
            self.assertEqual((await self.complete(nonce, response=value)).status_code, 502)
            self.assertIsNone(await gws._get_chat_token(self.other, "u", "c"))

    async def test_namespace_changes_on_secret_rotation(self):
        await self.save()
        self.tools.valves.google_client_secret = "rotated"
        gws._setup(self.app, self.tools.valves)
        self.assertIsNone(await gws._get_chat_token(self.app, "u", "c"))

    async def test_key_tuple_and_cluster_slot(self):
        key = gws._state_key(self.app, "token", "u:v", "c")
        other = gws._state_key(self.app, "token", "u", "v:c")
        self.assertNotEqual(key, other)
        self.assertEqual(key.split("}")[0], gws._state_key(self.app, "pending", "nonce").split("}")[0])

    async def test_tool_surface_preserved(self):
        names = [n for n in dir(self.tools) if not n.startswith("_") and inspect.ismethod(getattr(self.tools, n))]
        self.assertEqual(names, ["gws_action", "gws_authorize"])
        self.assertIn("__request__", inspect.signature(self.tools.gws_action).parameters)

    async def test_modal_cancellation_releases_pending_flow(self):
        async def cancel(event):
            return False
        result = await self.tools.gws_authorize("calendar.readonly", __user__={"id": "u"},
            __chat_id__="c", __request__=SimpleNamespace(app=self.app), __event_call__=cancel)
        self.assertTrue(result.startswith("AUTH_CANCELLED:"))
        self.assertIn("state", await self.begin())

    async def test_pending_flow_is_a_model_visible_status(self):
        await self.begin()
        result = await self.tools.gws_authorize("calendar.readonly", __user__={"id": "u"},
            __chat_id__="c", __request__=SimpleNamespace(app=self.other))
        self.assertTrue(result.startswith("AUTH_PENDING:"))

    async def test_callback_namespace_survives_concurrent_config_binding(self):
        # A task's auth keys must not switch namespaces when another task
        # rebinds the shared app to rotated OAuth credentials.
        nonce = (await self.begin())["state"][0]
        original = gws._state_key(self.app, "pending", nonce)

        async def rotate():
            changed = self.tools.Valves(**self.tools.valves.model_dump())
            changed.google_client_secret = "rotated"
            gws._setup(self.app, changed)

        await asyncio.create_task(rotate())
        self.assertEqual(gws._state_key(self.app, "pending", nonce), original)
        self.assertIsNotNone(await gws._pop_pending(self.app, nonce))


class MemoryTests(StateContract, unittest.IsolatedAsyncioTestCase):
    pass


@unittest.skipUnless(os.environ.get("REDIS_URL"), "REDIS_URL not configured")
class RedisTests(StateContract, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        from redis.asyncio import Redis
        self.app.state.redis = Redis.from_url(os.environ["REDIS_URL"])
        self.other = FastAPI()
        self.other.state.redis = Redis.from_url(os.environ["REDIS_URL"])
        self.clients = [self.app.state.redis, self.other.state.redis]
        gws._setup(self.other, self.tools.valves)

    async def test_concurrent_nonce_consume(self):
        nonce = (await self.begin())["state"][0]
        values = await asyncio.gather(gws._pop_pending(self.app, nonce), gws._pop_pending(self.other, nonce))
        self.assertEqual(sum(value is not None for value in values), 1)

    async def test_concurrent_first_consent(self):
        results = await asyncio.gather(self.begin(), self.begin(app=self.other), return_exceptions=True)
        self.assertEqual(sum(isinstance(r, gws._AuthorizationPending) for r in results), 1)

    async def test_outage_does_not_fall_back(self):
        class Broken:
            async def get(self, *args):
                raise ConnectionError("must not expose credentials")
        healthy = self.app.state.redis
        try:
            self.app.state.redis = Broken()
            with self.assertRaises(gws._StateUnavailable):
                await gws._get_chat_token(self.app, "u", "c")
            request = SimpleNamespace(app=self.app)
            result = await self.tools.gws_authorize(__request__=request, __user__={"id": "u"}, __chat_id__="c")
            self.assertTrue(result.startswith("AUTH_UNAVAILABLE:"))
            self.assertNotIn("credentials", result)
        finally:
            self.app.state.redis = healthy


if __name__ == "__main__":
    unittest.main()
