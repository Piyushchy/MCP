import json

import pytest

from tests.admin_helpers import HOST, PASS, demo, rig

CANARY = "canary-s3cr3t-7f3a91c2"
NEWPASS = "brand new admin passphrase " + CANARY[:6]


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for k in ("GITHUB_TOKEN", "DOCS_AUTHORIZATION", "INVOCATION_ID", "MCPGATE_SUPERVISED"):
        monkeypatch.delenv(k, raising=False)


def all_audit(r):
    out = ""
    for f in sorted(r.tmp.glob("audit.jsonl*")):
        if f.suffix != ".lock":
            out += f.read_text()
    return out


async def test_requires_login_csrf_and_host(tmp_path):
    async with rig(tmp_path) as r:
        assert (await r.post("/api/audit/settings", {"keep": 3}, csrf=False)).status_code == 403
        bad = await r.c.post("/api/audit/settings", headers={**r.headers(), "origin": "http://evil.example"}, content='{"keep":3}')
        assert bad.status_code == 403
        assert (await r.c.get("/api/audit", headers={"host": "evil.example"})).status_code in (400, 403, 421)
        r.c.cookies.clear()
        for path in ("/api/audit", "/api/audit/download"):
            assert (await r.get(path)).status_code == 401
        assert (await r.c.post("/api/audit/settings", headers={"host": HOST, "origin": f"http://{HOST}", "content-type": "application/json"}, content="{}")).status_code == 401


async def test_page_shows_calls_and_admin_events_newest_first_with_filters(tmp_path):
    async with rig(tmp_path) as r:
        await r.hub.call("demo.echo", {"text": "hi"})
        await r.hub.call("demo.add", {"a": 1, "b": 2})
        await r.post("/api/backends/demo/test")
        d = (await r.get("/api/audit")).json()
        assert d["settings"]["enabled"] and d["backends"] == ["demo"] and "ok" in d["statuses"]
        ts = [e["ts"] for e in d["entries"]]
        assert ts == sorted(ts, reverse=True) and d["entries"][0].get("event") == "admin_backend_test"
        calls = (await r.get("/api/audit?kind=call")).json()["entries"]
        assert [e["tool"] for e in calls] == ["demo.add", "demo.echo"] and all(e["status"] == "ok" for e in calls)
        assert [e["event"] for e in (await r.get("/api/audit?kind=admin")).json()["entries"]][:2] == ["admin_backend_test", "admin_setup"]
        assert len((await r.get("/api/audit?tool=echo&backend=demo&status=ok")).json()["entries"]) == 1
        assert (await r.get("/api/audit?q=nothing-like-this")).json()["entries"] == []
        assert len((await r.get("/api/audit?limit=1")).json()["entries"]) == 1
        assert d["files"][0]["name"] == "audit.jsonl"


async def test_paging_with_cursor(tmp_path):
    async with rig(tmp_path) as r:
        for i in range(12):
            await r.hub.call("demo.echo", {"text": f"n{i}"})
        first = (await r.get("/api/audit?kind=call&limit=5")).json()
        second = (await r.get(f"/api/audit?kind=call&limit=5&cursor={first['next']}")).json()
        third = (await r.get(f"/api/audit?kind=call&limit=5&cursor={second['next']}")).json()
        texts = [e["args"]["text"] for e in first["entries"] + second["entries"] + third["entries"]]
        assert texts == [f"n{i}" for i in range(11, -1, -1)] and third["next"] is None


@pytest.mark.parametrize("q", ["limit=0", "limit=500", "limit=x", "cursor=../../x", "kind=bogus", "since=nan", "until=inf", "since=abc", "q=" + "a" * 201, "tool=" + "a" * 201])
async def test_bad_query_values_are_400(tmp_path, q):
    async with rig(tmp_path) as r:
        assert (await r.get("/api/audit?" + q)).status_code == 400


async def test_hostile_content_is_returned_as_data_only(tmp_path):
    evil = "<img src=x onerror=alert(1)><script>alert(2)</script>"
    async with rig(tmp_path) as r:
        await r.hub.call("demo.echo", {"text": evil})
        resp = await r.get("/api/audit?kind=call")
        assert resp.headers["content-type"].startswith("application/json") and resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.json()["entries"][0]["args"]["text"] == evil
        assert "content-security-policy" in resp.headers


async def test_download_is_the_whole_log_as_an_attachment(tmp_path):
    async with rig(tmp_path) as r:
        await r.hub.call("demo.echo", {"text": "one"})
        resp = await r.get("/api/audit/download")
        assert resp.status_code == 200 and "attachment" in resp.headers["content-disposition"] and resp.headers["content-type"].startswith("application/x-ndjson")
        lines = [json.loads(x) for x in resp.text.splitlines()]
        assert lines[0]["event"] == "admin_setup" and lines[-1]["tool"] == "demo.echo"


async def test_download_without_a_log_is_404(tmp_path):
    async with rig(tmp_path) as r:
        r.hub.audit.path.unlink()
        assert (await r.get("/api/audit/download")).status_code == 404
        assert (await r.get("/api/audit")).json()["entries"] == []


async def test_settings_turn_off_on_and_resize(tmp_path):
    async with rig(tmp_path) as r:
        assert (await r.post("/api/audit/settings", {"max_mb": 2, "keep": 7})).json()["settings"]["max_mb"] == 2
        assert r.hub.audit.max_bytes == 2 * 1024 * 1024 and r.hub.audit.keep == 7
        assert "audit_max_mb = 2" in r.file_text() and "audit_keep = 7" in r.file_text()
        off = (await r.post("/api/audit/settings", {"enabled": False})).json()["settings"]
        assert off["enabled"] is False and r.hub.audit.path is None
        size = (r.tmp / "audit.jsonl").stat().st_size
        await r.hub.call("demo.echo", {"text": "unlogged"})
        assert (r.tmp / "audit.jsonl").stat().st_size == size
        assert (await r.get("/api/audit")).json()["entries"] == []
        on = (await r.post("/api/audit/settings", {"enabled": True})).json()["settings"]
        assert on["enabled"] and on["file"] == str(r.tmp / "audit.jsonl")
        await r.hub.call("demo.echo", {"text": "logged again"})
        assert "logged again" in all_audit(r) and "unlogged" not in all_audit(r)
        assert "admin_audit_settings" in all_audit(r)


@pytest.mark.parametrize("bad", [{}, {"max_mb": 0}, {"max_mb": 1001}, {"max_mb": "5"}, {"max_mb": True}, {"keep": 0}, {"keep": 51}, {"keep": 1.5},
                                 {"enabled": "yes"}, {"surprise": 1}, {"max_mb": 5, "surprise": 1}])
async def test_bad_settings_change_nothing(tmp_path, bad):
    async with rig(tmp_path) as r:
        before = r.file_text()
        assert (await r.post("/api/audit/settings", bad)).status_code == 400
        assert r.file_text() == before


async def test_the_gateway_rotates_for_real_when_the_limit_is_small(tmp_path):
    async with rig(tmp_path) as r:
        r.hub.audit.max_bytes = 1500
        for i in range(60):
            await r.hub.call("demo.echo", {"text": "x" * 40 + str(i)})
        d = (await r.get("/api/audit?kind=call&limit=200")).json()
        assert len(d["files"]) > 1 and all(f["bytes"] <= 1700 for f in d["files"])
        assert d["entries"][0]["args"]["text"].endswith("59")
        assert all((f.stat().st_mode & 0o777) == 0o600 for f in r.tmp.glob("audit.jsonl*"))


# -- nothing secret ever reaches the log --------------------------------------------------------------------------
async def test_no_secret_reaches_the_audit_log_whatever_the_admin_does(tmp_path):
    async with rig(tmp_path, {}) as r:
        secrets_seen = [PASS, NEWPASS, CANARY, "Bearer " + CANARY, "wrong-" + CANARY]
        # failed sign-ins, failed setup and failed step-up with canary values
        await r.c.post("/api/login", headers=r.headers(csrf=False), content=json.dumps({"passphrase": "wrong-" + CANARY}))
        await r.c.post("/api/setup", headers=r.headers(csrf=False), content=json.dumps({"code": "wrong-" + CANARY, "passphrase": "wrong-" + CANARY}))
        await r.post("/api/stepup", {"passphrase": "wrong-" + CANARY})
        await r.stepup()
        # backend with a secret header, then a tool call carrying it
        add = {"kind": "remote", "name": "docs", "transport": "http", "url": "https://mcp.example.com/mcp", "start_timeout": 5, "description": "d",
               "headers": [{"name": "Authorization", "value": "Bearer " + CANARY, "secret": True}], "confirm": True}
        assert (await r.post("/api/backends/add", add)).status_code == 200
        r.hub.audit.log(tool="docs.x", args={"token": CANARY, "note": "Bearer " + CANARY, "password": "p", "nested": {"api_key": CANARY}}, status="ok")
        # remote page: passphrase and token
        assert (await r.post("/api/remote/passphrase", {"passphrase": NEWPASS})).status_code == 200
        token = (await r.post("/api/remote/token")).json()["token"]
        secrets_seen.append(token)
        await r.post("/api/remote/settings", {"public_url": "https://box.tail1234.ts.net", "oauth_enabled": True})
        await r.post("/api/settings/custom-commands", {"enabled": True, "confirm": CANARY})
        await r.post("/api/audit/settings", {"max_mb": 3})
        assert (await r.post("/api/backends/docs/remove", {"confirm": True, "delete_secrets": True})).status_code == 200
        # change the admin passphrase last (a wrong attempt first)
        await r.post("/api/passphrase", {"current": "wrong-" + CANARY, "new": CANARY * 2})
        assert (await r.post("/api/passphrase", {"current": PASS, "new": NEWPASS})).status_code == 200
        text = all_audit(r)
        assert text.count("\n") >= 11, text
        for s in secrets_seen + [CANARY * 2]:
            assert s not in text, f"{s!r} leaked into the audit log"
        assert "scrypt" not in text and "csrf" not in text.lower()
        events = {json.loads(x).get("event") for x in text.splitlines()}
        assert {"admin_login_failed", "admin_backend_add", "admin_backend_remove", "admin_oauth_passphrase_changed", "admin_token_created",
                "admin_passphrase_changed", "admin_audit_settings"} <= events
