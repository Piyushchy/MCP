import asyncio
import json
import socket

import httpx
import pytest
from mcp.shared.auth import OAuthClientInformationFull

from mcpgate.oauth import GatewayOAuth
from mcpgate.remote import Restarter
from tests.admin_helpers import HOST, PASS, rig

URL = "https://box.tail1234.ts.net"
DOC = {"issuer": URL, "authorization_endpoint": URL + "/authorize", "token_endpoint": URL + "/token", "registration_endpoint": URL + "/register"}
NEW = "an entirely new passphrase"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for k in ("INVOCATION_ID", "MCPGATE_SUPERVISED"):
        monkeypatch.delenv(k, raising=False)


def public(host, port=None, type=None):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


def wire(r, handler=None):
    seen = []

    def default(request):
        seen.append((request.url.host, request.url.path))
        if request.url.path == "/mcp":
            return httpx.Response(401, headers={"www-authenticate": "Bearer"})
        return httpx.Response(200, json=DOC)
    r.ctx.check_transport = httpx.MockTransport(handler or default)
    r.ctx.resolve = public
    return seen


async def signed_in_app(r, name="claude.ai", *, rec=None):
    """A real gateway provider on the same state file, with one client signed in. Returns (provider, client, token)."""
    prov = GatewayOAuth(URL, passphrase=PASS, state_path=r.tmp / "oauth.json")
    client = OAuthClientInformationFull(client_id=f"c-{name}", client_name=name, redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
                                        token_endpoint_auth_method="none")
    await prov.register_client(client)
    tok = prov._issue(client.client_id, [], None)
    return prov, client, tok


async def set_url(r, url=URL):
    resp = await r.post("/api/remote/settings", {"public_url": url})
    assert resp.status_code == 200, resp.text


# -- access control --------------------------------------------------------------------------------------
async def test_every_route_needs_login_csrf_and_the_right_host(tmp_path):
    async with rig(tmp_path) as r:
        posts = ["settings", "passphrase", "token", "token/remove", "check", "sessions/abc/signout", "clients/abc/remove", "signout-all", "restart"]
        for p in posts:
            assert (await r.post("/api/remote/" + p, {}, csrf=False)).status_code == 403, p
            bad = await r.c.post("/api/remote/" + p, headers={**r.headers(), "origin": "http://evil.example"}, content="{}")
            assert bad.status_code == 403, p
            wrong = await r.c.post("/api/remote/" + p, headers={**r.headers(), "host": "evil.example"}, content="{}")
            assert wrong.status_code in (400, 403, 421), p
        assert (await r.c.get("/api/remote", headers={"host": "evil.example"})).status_code in (400, 403, 421)
        r.c.cookies.clear()
        assert (await r.get("/api/remote")).status_code == 401
        for p in posts:
            assert (await r.c.post("/api/remote/" + p, headers={"host": HOST, "origin": f"http://{HOST}", "content-type": "application/json"},
                                   content="{}")).status_code == 401, p


# -- settings ---------------------------------------------------------------------------------------------
async def test_settings_save_and_reach_the_file(tmp_path):
    async with rig(tmp_path) as r:
        resp = await r.post("/api/remote/settings", {"public_url": URL + "/", "port": 9100, "allow_hosts": ["box.tail1234.ts.net"], "oauth_enabled": True})
        assert resp.status_code == 200
        s = resp.json()["settings"]
        assert s["public_url"] == URL and s["port"] == 9100 and s["oauth_enabled"] is True
        text = r.file_text()
        assert URL in text and "9100" in text
        assert "admin_remote_settings" in r.audit_text()


@pytest.mark.parametrize("data", [{"public_url": "http://box.example.com"}, {"public_url": "https://box.example.com/mcp"}, {"port": 8767}, {"port": 80},
                                  {"allow_hosts": "x"}, {"oauth_enabled": "yes"}, {}, {"oauth_enabled": True}])
async def test_bad_settings_are_rejected_and_change_nothing(tmp_path, data):
    async with rig(tmp_path) as r:
        before = r.file_text()
        resp = await r.post("/api/remote/settings", data)
        assert resp.status_code == 400 and resp.json()["error"]
        assert r.file_text() == before


async def test_state_never_carries_secret_values(tmp_path):
    async with rig(tmp_path) as r:
        await r.stepup()
        assert (await r.post("/api/remote/passphrase", {"passphrase": NEW})).status_code == 200
        made = (await r.post("/api/remote/token")).json()
        token = made["token"]
        for _ in range(2):
            text = (await r.get("/api/remote")).text
            assert NEW not in text and token not in text and PASS not in text
        state = (await r.get("/api/remote")).json()
        assert state["passphrase"]["set"] and state["token"]["set"] and set(state["token"]) == {"set", "from_env", "updated"}
        assert NEW not in r.audit_text() and token not in r.audit_text() and "scrypt" not in r.audit_text()


# -- passphrase and token ----------------------------------------------------------------------------------
async def test_passphrase_and_token_need_step_up(tmp_path):
    async with rig(tmp_path) as r:
        for path, data in [("passphrase", {"passphrase": NEW}), ("token", {}), ("restart", {})]:
            resp = await r.post("/api/remote/" + path, data)
            assert resp.status_code == 403 and resp.json()["stepup"] is True, path
        state = (await r.get("/api/remote")).json()
        assert not state["passphrase"]["set"] and not state["token"]["set"]


async def test_passphrase_validation_and_hash_storage(tmp_path):
    async with rig(tmp_path) as r:
        await r.stepup()
        for bad in [{"passphrase": "short"}, {"passphrase": 12345678901234}, {}, {"passphrase": NEW, "keep_sessions": "yes"}]:
            assert (await r.post("/api/remote/passphrase", bad)).status_code == 400
        assert (await r.post("/api/remote/passphrase", {"passphrase": NEW})).status_code == 200
        assert r.auth.store.verify("oauth_passphrase", NEW) and not r.auth.store.verify("oauth_passphrase", "wrong")
        assert NEW not in (r.tmp / "auth.json").read_text()


async def test_changing_passphrase_keeps_signed_in_apps_unless_asked(tmp_path):
    async with rig(tmp_path) as r:
        prov, client, tok = await signed_in_app(r)
        await r.stepup()
        assert (await r.post("/api/remote/passphrase", {"passphrase": NEW})).status_code == 200
        assert await prov.load_access_token(tok.access_token) is not None
        assert (await r.post("/api/remote/passphrase", {"passphrase": NEW + " two", "keep_sessions": False})).status_code == 200
        assert await prov.load_access_token(tok.access_token) is None
        assert (await r.get("/api/remote")).json()["sessions"] == []


async def test_token_is_shown_once_and_turns_the_setting_on(tmp_path):
    async with rig(tmp_path) as r:
        await r.stepup()
        resp = await r.post("/api/remote/token")
        body = resp.json()
        assert len(body["token"]) >= 32 and body["settings"]["static_token_enabled"] is True
        assert r.auth.store.verify("static_token", body["token"]) and body["token"] not in (r.tmp / "auth.json").read_text()
        again = (await r.post("/api/remote/token")).json()
        assert again["token"] != body["token"] and not r.auth.store.verify("static_token", body["token"])
        gone = (await r.post("/api/remote/token/remove")).json()
        assert gone["token"]["set"] is False and "token" not in gone["token"]


# -- the connection check ----------------------------------------------------------------------------------
async def test_check_needs_a_saved_address(tmp_path):
    async with rig(tmp_path) as r:
        wire(r)
        assert (await r.post("/api/remote/check")).status_code == 400


async def test_check_only_ever_contacts_the_saved_address(tmp_path):
    async with rig(tmp_path) as r:
        await set_url(r)
        seen = wire(r)
        for evil in [{"url": "http://169.254.169.254/latest/meta-data"}, {"public_url": "https://evil.example"}, {"host": "10.0.0.1"}]:
            r.ctx.last_check = 0.0
            resp = await r.post("/api/remote/check", evil)
            assert resp.status_code == 200 and resp.json()["url"] == URL
        assert {h for h, _ in seen} == {"box.tail1234.ts.net"}


async def test_check_reports_and_is_rate_limited(tmp_path):
    async with rig(tmp_path) as r:
        await set_url(r)
        wire(r)
        first = await r.post("/api/remote/check")
        assert first.status_code == 200
        assert [x["ok"] for x in first.json()["results"]] == [True, True, True]
        second = await r.post("/api/remote/check")
        assert second.status_code == 429 and second.json()["error"]
        assert "admin_remote_check" in r.audit_text()


async def test_check_refuses_a_private_resolution(tmp_path):
    async with rig(tmp_path) as r:
        await set_url(r)
        seen = wire(r)
        r.ctx.resolve = lambda host, port=None, type=None: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
        resp = await r.post("/api/remote/check")
        assert resp.status_code == 200 and resp.json()["results"][0]["ok"] is False and seen == []


# -- signed-in apps ------------------------------------------------------------------------------------------
async def test_sign_out_one_session_takes_effect_on_the_running_gateway(tmp_path):
    async with rig(tmp_path) as r:
        prov, client, one = await signed_in_app(r, "claude.ai")
        two = prov._issue(client.client_id, [], None)
        state = (await r.get("/api/remote")).json()
        assert len(state["sessions"]) == 2 and state["clients"][0]["name"] == "claude.ai" and state["clients"][0]["sessions"] == 2
        assert one.access_token not in json.dumps(state) and one.refresh_token not in json.dumps(state)
        sid = state["sessions"][0]["id"]
        resp = await r.post(f"/api/remote/sessions/{sid}/signout")
        assert resp.status_code == 200 and len(resp.json()["sessions"]) == 1
        alive = [t for t in (one, two) if await prov.load_access_token(t.access_token)]
        assert len(alive) == 1
        assert (await r.post(f"/api/remote/sessions/{sid}/signout")).status_code == 404


async def test_remove_app_and_sign_out_everyone(tmp_path):
    async with rig(tmp_path) as r:
        prov, a, ta = await signed_in_app(r, "one")
        _, b, tb = await signed_in_app(r, "two")
        resp = await r.post(f"/api/remote/clients/{a.client_id}/remove")
        assert resp.status_code == 200 and [c["name"] for c in resp.json()["clients"]] == ["two"]
        assert await prov.load_access_token(ta.access_token) is None and await prov.load_access_token(tb.access_token) is not None
        assert (await r.post(f"/api/remote/clients/{a.client_id}/remove")).status_code == 404
        assert (await r.post("/api/remote/signout-all")).status_code == 200
        assert await prov.load_access_token(tb.access_token) is None
        assert (await r.get("/api/remote")).json()["clients"] == []


@pytest.mark.parametrize("bad", ["a b", "x" * 200, "a%2Fb", "..", "a;b"])
async def test_odd_ids_are_not_found(tmp_path, bad):
    async with rig(tmp_path) as r:
        assert (await r.post(f"/api/remote/sessions/{bad}/signout")).status_code in (404, 405)
        assert (await r.post(f"/api/remote/clients/{bad}/remove")).status_code in (404, 405)


async def test_rotating_a_refresh_token_keeps_one_session(tmp_path):
    async with rig(tmp_path) as r:
        prov, client, tok = await signed_in_app(r)
        old = await prov.load_refresh_token(client, tok.refresh_token)
        new = await prov.exchange_refresh_token(client, old, [])
        sessions = (await r.get("/api/remote")).json()["sessions"]
        assert len(sessions) == 1
        await r.post(f"/api/remote/sessions/{sessions[0]['id']}/signout")
        assert await prov.load_access_token(new.access_token) is None


# -- restart ---------------------------------------------------------------------------------------------------
async def test_restart_required_follows_what_the_gateway_started_with(tmp_path):
    running = {"listener": False, "oauth": False, "static": False, "public_url": "", "port": 8766, "hosts": []}
    async with rig(tmp_path, running=running) as r:
        assert (await r.get("/api/remote")).json()["restart"]["required"] is False
        await set_url(r)
        await r.stepup()
        await r.post("/api/remote/passphrase", {"passphrase": NEW})
        await r.post("/api/remote/settings", {"oauth_enabled": True})
        state = (await r.get("/api/remote")).json()
        assert state["restart"]["required"] is True and state["restart"]["service"] is True and state["ready"]["oauth"] is True


async def test_not_a_service_means_no_restart_needed(tmp_path):
    async with rig(tmp_path) as r:
        await set_url(r)
        assert (await r.get("/api/remote")).json()["restart"]["service"] is False


async def test_restart_is_refused_when_nothing_would_start_it_again(tmp_path):
    async with rig(tmp_path) as r:
        await r.stepup()
        resp = await r.post("/api/remote/restart")
        assert resp.status_code == 409 and "service" in resp.json()["error"]
    restarter = Restarter()
    async with rig(tmp_path / "b", restarter=restarter, running={"listener": False}) as r:
        (tmp_path / "b").mkdir(exist_ok=True)
        await r.stepup()
        resp = await r.post("/api/remote/restart")
        assert resp.status_code == 409 and "service manager" in resp.json()["error"] and not restarter.requested


async def test_restart_under_a_supervisor_stops_the_service_after_answering(tmp_path, monkeypatch):
    monkeypatch.setenv("MCPGATE_SUPERVISED", "1")
    restarter, stopped = Restarter(), []
    restarter.attach(lambda: stopped.append(1))
    async with rig(tmp_path, restarter=restarter, running={"listener": False}) as r:
        await r.stepup()
        resp = await r.post("/api/remote/restart")
        assert resp.status_code == 200 and resp.json() == {"restarting": True} and not restarter.requested
        await asyncio.sleep(1.0)
        assert restarter.requested and stopped == [1]
        assert "admin_restart" in r.audit_text()
