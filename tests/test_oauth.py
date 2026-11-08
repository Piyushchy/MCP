"""OAuth for claude.ai: a full authorization-code + PKCE flow against a live gateway."""
import asyncio
import base64
import hashlib
import json
import secrets
import socket
import time
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mcpgate import oauth as oauthmod, serve, server
from mcpgate.config import Settings
from tests.test_serve import _Both

PASS = "correct horse battery"
CB = "https://claude.ai/api/mcp/auth_callback"


def pkce():
    verifier = secrets.token_urlsafe(48)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


@asynccontextmanager
async def running(tmp_path, demo_cfg=None, static_token=None, state=None):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    oa = oauthmod.GatewayOAuth(base, PASS, state or tmp_path / "oauth.json", static_token=static_token)
    st = Settings()
    if demo_cfg:
        st.backends["demo"] = demo_cfg()
    app, hub = server.build(st, oauth=oa)
    srv = serve.make_http_server(app, "127.0.0.1", port, None, oauth=True)
    task = asyncio.create_task(srv.serve())
    for _ in range(100):
        if srv.started:
            break
        await asyncio.sleep(0.05)
    try:
        yield base, oa, hub
    finally:
        srv.should_exit = True
        await asyncio.wait_for(task, 20)
        await hub.stop()


async def register(h, base, redirect=CB, name="Claude"):
    r = await h.post(f"{base}/register", json={
        "redirect_uris": [redirect], "token_endpoint_auth_method": "none", "client_name": name,
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "scope": "mcp"})
    return r


async def start(h, base, client_id, challenge, redirect=CB, state="st8"):
    r = await h.get(f"{base}/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect, "code_challenge": challenge,
        "code_challenge_method": "S256", "state": state, "scope": "mcp", "resource": f"{base}/mcp"})
    assert r.status_code == 302, r.text
    loc = r.headers["location"]
    assert loc.startswith(f"{base}/consent?req=")
    return parse_qs(urlparse(loc).query)["req"][0]


async def approve(h, base, req, passphrase=PASS, decision="approve"):
    return await h.post(f"{base}/consent", data={"req": req, "passphrase": passphrase, "decision": decision})


async def get_code(h, base, client_id, challenge):
    req = await start(h, base, client_id, challenge)
    r = await approve(h, base, req)
    assert r.status_code == 303
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert r.headers["location"].startswith(CB) and q["state"] == ["st8"]
    return q["code"][0]


async def token(h, base, **form):
    return await h.post(f"{base}/token", data=form)


async def full_login(h, base):
    cid = (await register(h, base)).json()["client_id"]
    verifier, challenge = pkce()
    code = await get_code(h, base, cid, challenge)
    r = await token(h, base, grant_type="authorization_code", code=code, redirect_uri=CB, client_id=cid, code_verifier=verifier)
    assert r.status_code == 200, r.text
    return cid, r.json(), code, verifier


async def test_discovery_and_the_401_claude_needs(tmp_path):
    async with running(tmp_path) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            r = await h.post(f"{base}/mcp", json={})
            assert r.status_code == 401
            assert "resource_metadata" in r.headers["www-authenticate"]
            meta_url = r.headers["www-authenticate"].split('resource_metadata="')[1].split('"')[0]
            prm = (await h.get(meta_url)).json()
            assert prm["resource"].rstrip("/") == f"{base}/mcp" and prm["authorization_servers"][0].rstrip("/") == base
            am = (await h.get(f"{base}/.well-known/oauth-authorization-server")).json()
            assert am["registration_endpoint"].endswith("/register") and "S256" in am["code_challenge_methods_supported"]
            assert am["authorization_endpoint"].endswith("/authorize") and am["token_endpoint"].endswith("/token")


async def test_only_allowed_redirect_hosts_can_register(tmp_path):
    async with running(tmp_path) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            assert (await register(h, base)).status_code == 201
            assert (await register(h, base, "http://localhost:3118/callback")).status_code == 201  # Claude Code
            for bad in ["https://evil.example/cb", "http://claude.ai/cb", "https://claude.ai.evil.example/cb"]:
                r = await register(h, base, bad)
                assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri", bad


async def test_full_flow_then_mcp_call_refresh_and_replay_defences(tmp_path, demo_cfg):
    async with running(tmp_path, demo_cfg) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            cid, tok, code, verifier = await full_login(h, base)
            assert tok["token_type"].lower() == "bearer" and tok["expires_in"] == oauthmod.ACCESS_TTL and tok["refresh_token"]

            # the code works exactly once
            again = await token(h, base, grant_type="authorization_code", code=code, redirect_uri=CB, client_id=cid, code_verifier=verifier)
            assert again.status_code == 400 and again.json()["error"] == "invalid_grant"

            # the access token really opens the MCP endpoint
            client = httpx.AsyncClient(headers={"Authorization": f"Bearer {tok['access_token']}"})
            async with _Both(client, streamable_http_client(f"{base}/mcp", http_client=client)) as (r, w, _):
                async with ClientSession(r, w) as c:
                    await c.initialize()
                    res = await c.call_tool("call_tool", {"name": "demo.add", "arguments": {"a": 1, "b": 2}})
                    assert res.content[0].text == "3"

            # refresh rotates: new pair works, the old refresh token is dead, and the old access token with it
            r2 = await token(h, base, grant_type="refresh_token", refresh_token=tok["refresh_token"], client_id=cid)
            assert r2.status_code == 200
            new = r2.json()
            assert new["access_token"] != tok["access_token"] and new["refresh_token"] != tok["refresh_token"]
            replay = await token(h, base, grant_type="refresh_token", refresh_token=tok["refresh_token"], client_id=cid)
            assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
            old_use = await h.post(f"{base}/mcp", json={}, headers={"Authorization": f"Bearer {tok['access_token']}"})
            assert old_use.status_code == 401
            new_use = await h.post(f"{base}/mcp", json={}, headers={"Authorization": f"Bearer {new['access_token']}", "Accept": "application/json, text/event-stream"})
            assert new_use.status_code != 401


async def test_wrong_pkce_verifier_and_wrong_client_are_refused(tmp_path):
    async with running(tmp_path) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            cid = (await register(h, base)).json()["client_id"]
            other = (await register(h, base)).json()["client_id"]
            verifier, challenge = pkce()
            code = await get_code(h, base, cid, challenge)
            bad = await token(h, base, grant_type="authorization_code", code=code, redirect_uri=CB, client_id=cid, code_verifier=pkce()[0])
            assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
            code = await get_code(h, base, cid, challenge)
            stolen = await token(h, base, grant_type="authorization_code", code=code, redirect_uri=CB, client_id=other, code_verifier=verifier)
            assert stolen.status_code == 400


async def test_consent_page_passphrase_deny_lockout_and_bad_links(tmp_path):
    async with running(tmp_path) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            cid = (await register(h, base, name="<script>alert(1)</script>")).json()["client_id"]
            _, challenge = pkce()
            req = await start(h, base, cid, challenge)
            page = await h.get(f"{base}/consent", params={"req": req})
            assert page.status_code == 200 and "claude.ai" in page.text
            assert "<script>alert(1)" not in page.text and "&lt;script&gt;" in page.text   # escaped
            assert page.headers["x-frame-options"] == "DENY" and "no-store" in page.headers["cache-control"]

            # invalid / unknown links
            assert (await h.get(f"{base}/consent", params={"req": "nope"})).status_code == 400
            assert (await approve(h, base, "nope")).status_code == 400

            # denying sends the user back with access_denied and uses the request up
            denied = await approve(h, base, req, decision="deny")
            assert denied.status_code == 303 and "error=access_denied" in denied.headers["location"] and "code=" not in denied.headers["location"]
            assert (await approve(h, base, req)).status_code == 400

            # wrong passphrases: 4 normal refusals, the 5th locks, and then even the right one is refused
            req = await start(h, base, cid, challenge)
            for _ in range(4):
                assert (await approve(h, base, req, passphrase="nope")).status_code == 401
            assert (await approve(h, base, req, passphrase="nope")).status_code == 429
            locked = await approve(h, base, req)
            assert locked.status_code == 429 and "code=" not in locked.headers.get("location", "")

            # the lock ends, and the right passphrase resets the counter
            real = time.time()
            oa._now = lambda: real + 120
            ok = await approve(h, base, req)
            assert ok.status_code == 303 and "code=" in ok.headers["location"]
            assert oa._fails == 0


async def test_pending_approvals_expire(tmp_path):
    async with running(tmp_path) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            cid = (await register(h, base)).json()["client_id"]
            req = await start(h, base, cid, pkce()[1])
            real = time.time()
            oa._now = lambda: real + oauthmod.PENDING_TTL + 1
            assert (await approve(h, base, req)).status_code == 400


async def test_access_tokens_expire(tmp_path):
    async with running(tmp_path) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            cid, tok, *_ = await full_login(h, base)
            real = time.time()
            oa._now = lambda: real + oauthmod.ACCESS_TTL + 5
            assert (await h.post(f"{base}/mcp", json={}, headers={"Authorization": f"Bearer {tok['access_token']}"})).status_code == 401
            # but the refresh token still works and gives a fresh one
            r = await token(h, base, grant_type="refresh_token", refresh_token=tok["refresh_token"], client_id=cid)
            assert r.status_code == 200


async def test_state_file_holds_only_hashes_survives_restart_and_is_private(tmp_path):
    state = tmp_path / "oauth.json"
    async with running(tmp_path, state=state) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            cid, tok, *_ = await full_login(h, base)
    text = state.read_text()
    assert tok["access_token"] not in text and tok["refresh_token"] not in text   # only hashes on disk
    assert (state.stat().st_mode & 0o777) == 0o600
    # a brand new gateway process on the same file still honours the token (the user does not log in again)
    fresh = oauthmod.GatewayOAuth("http://127.0.0.1:1", PASS, state)
    assert await fresh.load_access_token(tok["access_token"]) is not None
    assert await fresh.load_access_token("not-a-token") is None
    assert await fresh.get_client(cid) is not None


async def test_revoke_endpoint_kills_the_whole_grant(tmp_path):
    async with running(tmp_path) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            cid, tok, *_ = await full_login(h, base)
            r = await h.post(f"{base}/revoke", data={"token": tok["access_token"], "client_id": cid, "client_secret": ""})
            assert r.status_code == 200
            assert await oa.load_access_token(tok["access_token"]) is None
            assert (await token(h, base, grant_type="refresh_token", refresh_token=tok["refresh_token"], client_id=cid)).status_code == 400


async def test_static_token_still_works_alongside_oauth(tmp_path):
    static = "s" * 40
    async with running(tmp_path, static_token=static) as (base, oa, hub):
        async with httpx.AsyncClient() as h:
            hdr = {"Accept": "application/json, text/event-stream"}
            assert (await h.post(f"{base}/mcp", json={}, headers={**hdr, "Authorization": f"Bearer {static}"})).status_code != 401
            assert (await h.post(f"{base}/mcp", json={}, headers={**hdr, "Authorization": "Bearer " + "x" * 40})).status_code == 401
            assert (await h.post(f"{base}/mcp", json={}, headers=hdr)).status_code == 401


def test_passphrase_must_be_long_enough(tmp_path):
    with pytest.raises(ValueError, match="at least"):
        oauthmod.GatewayOAuth("https://x.example", "short", tmp_path / "s.json")
