"""Signing in to a remote backend that uses OAuth: mcpgate as the client, a real OAuth-protected gateway as the server."""
import asyncio
import json
import socket
import stat
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlparse

import httpx

from mcpgate import oauth as oauthmod, serve, server
from mcpgate.config import Backend, Settings
from tests.admin_helpers import demo, rig
from tests.test_oauth import PASS as PROVIDER_PASS


@asynccontextmanager
async def provider(tmp_path):
    """A server that asks for sign-in, with the demo tools behind it."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    oa = oauthmod.GatewayOAuth(base, PROVIDER_PASS, tmp_path / "provider-oauth.json", redirect_hosts=("127.0.0.1",))
    st = Settings()
    st.backends["demo"] = demo()
    app, hub = server.build(st, oauth=oa)
    srv = serve.make_http_server(app, "127.0.0.1", port, None, oauth=True)
    task = asyncio.create_task(srv.serve())
    for _ in range(100):
        if srv.started:
            break
        await asyncio.sleep(0.05)
    try:
        yield base, oa
    finally:
        srv.should_exit = True
        await asyncio.wait_for(task, 20)
        await hub.stop()


async def browser_login(auth_url: str) -> tuple[str, str]:
    """What the owner's browser does on the server's own pages: open the link, type the passphrase, approve."""
    async with httpx.AsyncClient(follow_redirects=False) as h:
        r = await h.get(auth_url)
        assert r.status_code == 302, r.text
        req = parse_qs(urlparse(r.headers["location"]).query)["req"][0]
        base = auth_url.split("/authorize")[0]
        r = await h.post(f"{base}/consent", data={"req": req, "passphrase": PROVIDER_PASS, "decision": "approve"})
        assert r.status_code == 303, r.text
        q = parse_qs(urlparse(r.headers["location"]).query)
        assert r.headers["location"].startswith("http://127.0.0.1:8767/oauth/callback")
        return q["code"][0], q["state"][0]


async def wait_for(r, name, predicate, seconds=20):
    for _ in range(int(seconds / 0.2)):
        row = next(b for b in (await r.get("/api/backends")).json()["backends"] if b["name"] == name)
        if predicate(row):
            return row
        await asyncio.sleep(0.2)
    raise AssertionError(f"timed out: {row}")


async def test_sign_in_connect_refresh_and_sign_out_without_a_token(tmp_path):
    async with provider(tmp_path) as (base, oa):
        mine = Backend(name="acct", transport="http", url=base + "/mcp", auth="oauth")
        async with rig(tmp_path / "gw", {"acct": mine}) as r:
            (tmp_path / "gw").mkdir(exist_ok=True)
            row = (await r.post("/api/backends/acct/test")).json()
            assert "sign-in" in json.dumps(row).lower() or row.get("ok") is False
            assert (await wait_for(r, "acct", lambda x: True))["signed_in"] is False

            resp = await r.post("/api/backends/acct/signin")
            assert resp.status_code == 200, resp.text
            url = resp.json()["url"]
            assert url.startswith(base + "/authorize") and resp.json()["redirect_uri"] == "http://127.0.0.1:8767/oauth/callback"
            assert (await wait_for(r, "acct", lambda x: x["signing_in"]))["signed_in"] is False

            code, state = await browser_login(url)
            # the provider sends the browser to the callback: no admin session is sent with that request
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=r.c._transport.app), base_url="http://127.0.0.1:8767") as anon:
                page = await anon.get(f"/oauth/callback?code={code}&state={state}", headers={"host": "127.0.0.1:8767"})
                assert page.status_code == 200 and "Signed in to acct" in page.text
                replay = await anon.get(f"/oauth/callback?code={code}&state={state}", headers={"host": "127.0.0.1:8767"})
                assert replay.status_code == 400
                assert (await anon.get("/oauth/callback?code=x&state=nope", headers={"host": "127.0.0.1:8767"})).status_code == 400
                assert (await anon.get("/oauth/callback?error=access_denied&state=nope", headers={"host": "127.0.0.1:8767"})).status_code == 400
                assert (await anon.get("/oauth/callback", headers={"host": "evil.example"})).status_code in (400, 403, 404, 421)
            row = await wait_for(r, "acct", lambda x: x["state"] == "connected" and x["signed_in"])
            assert not row["error"]
            tested = (await r.post("/api/backends/acct/test")).json()
            assert tested.get("ok") is True and tested.get("tools"), tested

            # the tokens are in a private file and nowhere else
            tokens_file = tmp_path / "gw" / "backend_oauth.json"
            data = json.loads(tokens_file.read_text())
            access = data["acct"]["tokens"]["access_token"]
            assert stat.S_IMODE(tokens_file.stat().st_mode) == 0o600
            for text in (r.file_text(), r.audit_text(), (await r.get("/api/backends")).text, (await r.get("/api/secrets")).text,
                         (await r.get("/api/backends/acct/edit")).text, resp.text):
                assert access not in text and data["acct"]["tokens"].get("refresh_token", "\0") not in text

            # a restart of the gateway keeps the sign-in
            await r.hub.backends["acct"].stop()
            assert (await r.post("/api/backends/acct/test")).status_code == 200
            await wait_for(r, "acct", lambda x: x["state"] == "connected")

            out = await r.post("/api/backends/acct/signout")
            assert out.status_code == 200 and out.json() == {"signed_out": True}
            row = await wait_for(r, "acct", lambda x: not x["signed_in"])
            await r.post("/api/backends/acct/test")
            assert "tokens" not in json.loads(tokens_file.read_text()).get("acct", {})
            events = [json.loads(x)["event"] for x in r.audit_text().splitlines() if "admin_backend_sign" in x]
            assert events[:2] == ["admin_backend_signin_start", "admin_backend_signin_done"] and events[-1] == "admin_backend_signout"


async def test_sign_in_endpoints_are_guarded_and_only_for_backends_that_use_it(tmp_path):
    mine = Backend(name="acct", transport="http", url="http://127.0.0.1:9/mcp", auth="oauth")
    async with rig(tmp_path, {"acct": mine, "demo": demo()}) as r:
        assert (await r.post("/api/backends/acct/signin", csrf=False)).status_code == 403
        assert (await r.post("/api/backends/demo/signin")).status_code == 400
        assert (await r.post("/api/backends/nope/signin")).status_code == 404
        resp = await r.post("/api/backends/acct/signin")          # nothing is listening there
        assert resp.status_code == 502 and "Traceback" not in resp.text
        r.c.cookies.clear()
        assert (await r.post("/api/backends/acct/signin")).status_code == 401
        assert (await r.get("/oauth/callback?state=x", headers={"host": "127.0.0.1:8767"}) if False else await r.get("/oauth/callback?state=x")).status_code == 400


async def test_add_and_edit_a_backend_that_signs_in(tmp_path):
    async with rig(tmp_path, {}) as r:
        resp = await r.post("/api/backends/add", {"kind": "remote", "name": "notes", "url": "https://notes.example.com/mcp", "auth": "oauth", "confirm": True})
        assert resp.status_code == 200, resp.text
        assert r.hub.backends["notes"].cfg.auth == "oauth" and 'auth = "oauth"' in r.file_text()
        assert (await r.post("/api/backends/add", {"kind": "remote", "name": "n2", "url": "https://x.example.com/mcp", "auth": "basic"})).status_code == 400
        assert (await r.post("/api/backends/notes/edit", {"auth": ""})).status_code == 200
        assert r.hub.backends["notes"].cfg.auth == "" and "auth" not in r.file_text()
        assert (await r.post("/api/backends/notes/edit", {"auth": "oauth"})).status_code == 200
        assert (await r.get("/api/backends/notes/edit")).json()["auth"] == "oauth"
