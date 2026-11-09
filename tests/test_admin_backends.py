import json
import sys
import time

import pytest

from mcpgate.config import Backend
from tests.admin_helpers import DEMO, HOST, demo, rig

CANARY = "canary-s3cr3t-7f3a91c2"


async def test_requires_login_and_csrf(tmp_path):
    async with rig(tmp_path) as r:
        r.c.cookies.clear()
        assert (await r.get("/api/backends")).status_code == 401
        assert (await r.post("/api/backends/demo/test", csrf=False)).status_code == 401
    (tmp_path / "second").mkdir()
    async with rig(tmp_path / "second") as r:
        for action in ["enable", "disable", "test", "restart", "remove"]:
            assert (await r.post(f"/api/backends/demo/{action}", csrf=False)).status_code == 403, action


async def test_listing_states_and_reasons(tmp_path):
    bad = Backend(name="broken", transport="stdio", command="/nonexistent/prog", start_timeout=5)
    async with rig(tmp_path, {"demo": demo(), "off": demo("off", enabled=False), "broken": bad}) as r:
        rows = {b["name"]: b for b in (await r.get("/api/backends")).json()["backends"]}
        assert rows["demo"]["state"] == "idle" and rows["off"]["state"] == "disabled" and rows["demo"]["source"] == "config"
        t = (await r.post("/api/backends/demo/test")).json()
        assert t["ok"] and t["tools"] >= 8 and t["backend"]["state"] == "connected"
        t = (await r.post("/api/backends/broken/test")).json()
        assert not t["ok"] and "/nonexistent/prog" in t["error"]
        rows = {b["name"]: b for b in (await r.get("/api/backends")).json()["backends"]}
        assert rows["demo"]["state"] == "connected" and rows["demo"]["tools_visible"] >= 8
        assert rows["broken"]["state"] == "error" and "nonexistent" in rows["broken"]["error"]
        assert rows["off"]["state"] == "disabled" and rows["off"]["error"] == ""


async def test_listing_matches_cli_list_semantics_for_policy_counts(tmp_path):
    async with rig(tmp_path, {"demo": demo(deny=["wipe", "delete_*"])}) as r:
        await r.post("/api/backends/demo/test")
        row = next(b for b in (await r.get("/api/backends")).json()["backends"] if b["name"] == "demo")
        hub_tools, _ = await r.hub.catalog("demo")
        assert row["tools_visible"] == len(hub_tools) and row["tools_hidden"] == 2 and row["has_policy"]


async def test_dropin_listed_read_only_with_path(tmp_path):
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / "notes.py").write_text('"""My notes."""\nfrom mcp.server.fastmcp import FastMCP\nFastMCP("notes").run()\n')
    from mcpgate import config as cfgmod
    from mcpgate import loader
    from mcpgate.config import Settings
    async with rig(tmp_path, {"demo": demo()}) as r:
        s = cfgmod.load(r.path)
        s.custom_dir = str(custom)
        cfgmod.save(s, r.path)
        await r.ctx.reloader.check(force=True)
        row = next(b for b in (await r.get("/api/backends")).json()["backends"] if b["name"] == "notes")
        assert row["source"] == "custom" and row["readonly"] and row["path"].endswith("notes.py")
        for action in ["disable", "enable"]:
            resp = await r.post(f"/api/backends/notes/{action}")
            assert resp.status_code == 400 and "drop-in" in resp.json()["error"]
        assert (await r.post("/api/backends/notes/remove", {"confirm": True})).status_code == 400


async def test_disable_then_enable_needs_stepup_for_commands(tmp_path):
    async with rig(tmp_path) as r:
        assert (await r.post("/api/backends/demo/disable")).json()["state"] == "disabled"
        assert "enabled = false" in r.file_text()
        resp = await r.post("/api/backends/demo/enable")
        assert resp.status_code == 403 and resp.json()["stepup"] is True
        assert "enabled = false" in r.file_text()                      # nothing changed
        await r.stepup()
        resp = await r.post("/api/backends/demo/enable")
        assert resp.status_code == 200 and resp.json()["enabled"] is True
        assert "enabled = false" not in r.file_text()


async def test_enable_remote_backend_does_not_need_stepup(tmp_path):
    remote = Backend(name="hosted", transport="http", url="https://example.invalid/mcp", enabled=False)
    async with rig(tmp_path, {"hosted": remote}) as r:
        assert (await r.post("/api/backends/hosted/enable")).status_code == 200


async def test_testing_a_disabled_backend_does_not_enable_it(tmp_path):
    async with rig(tmp_path, {"off": demo("off", enabled=False)}) as r:
        t = (await r.post("/api/backends/off/test")).json()
        assert t["ok"] and t["backend"]["state"] == "disabled"
        assert not r.hub.backends["off"].connected


async def test_test_never_shows_secret_values(tmp_path):
    bad = Backend(name="leaky", transport="stdio", command="/nonexistent/${TOK}", start_timeout=5)
    async with rig(tmp_path, {"leaky": bad}, secrets={"TOK": CANARY}) as r:
        t = (await r.post("/api/backends/leaky/test")).json()
        assert not t["ok"] and CANARY not in json.dumps(t)
        assert CANARY not in (await r.get("/api/backends")).text
        assert CANARY not in r.audit_text()


async def test_test_connection_is_bounded_by_start_timeout(tmp_path):
    slow = Backend(name="slow", transport="stdio", command=sys.executable, args=["-c", "import time; time.sleep(60)"], start_timeout=1)
    async with rig(tmp_path, {"slow": slow}) as r:
        t0 = time.monotonic()
        t = (await r.post("/api/backends/slow/test")).json()
        assert time.monotonic() - t0 < 8 and not t["ok"] and t["error"]


async def test_restart(tmp_path):
    async with rig(tmp_path) as r:
        await r.post("/api/backends/demo/test")
        first = r.hub.backends["demo"]._task
        row = (await r.post("/api/backends/demo/restart")).json()
        assert row["state"] == "connected" and r.hub.backends["demo"]._task is not first
        await r.post("/api/backends/demo/disable")
        assert (await r.post("/api/backends/demo/restart")).status_code == 400


async def test_remove_needs_confirmation_and_reports_impact(tmp_path):
    github = Backend(name="github", transport="http", url="https://example.invalid/mcp",
                     headers={"Authorization": "Bearer ${GH_TOKEN}"}, deny=["delete_*"])
    other = Backend(name="other", transport="http", url="https://example.invalid/x", headers={"X": "${SHARED}"})
    github.headers["Y"] = "${SHARED}"
    async with rig(tmp_path, {"github": github, "other": other}, secrets={"GH_TOKEN": CANARY, "SHARED": "shared-value-1"}) as r:
        imp = (await r.get("/api/backends/github/impact")).json()
        assert imp == {"has_policy": True, "secrets_only_used_here": ["GH_TOKEN"]}
        assert (await r.post("/api/backends/github/remove", {})).status_code == 400
        assert "github" in r.hub.backends
        resp = await r.post("/api/backends/github/remove", {"confirm": True})
        assert resp.json() == {"removed": "github", "secrets_deleted": []}
        assert "github" not in r.hub.backends and "github" not in r.file_text() and r.secrets.has("GH_TOKEN")


async def test_remove_can_delete_secrets_only_it_used(tmp_path):
    github = Backend(name="github", transport="http", url="https://example.invalid/mcp",
                     headers={"A": "${GH_TOKEN}", "B": "${SHARED}"})
    other = Backend(name="other", transport="http", url="https://example.invalid/x", headers={"X": "${SHARED}"})
    async with rig(tmp_path, {"github": github, "other": other}, secrets={"GH_TOKEN": CANARY, "SHARED": "shared-value-1"}) as r:
        resp = await r.post("/api/backends/github/remove", {"confirm": True, "delete_secrets": True})
        assert resp.json()["secrets_deleted"] == ["GH_TOKEN"]
        assert not r.secrets.has("GH_TOKEN") and r.secrets.has("SHARED")
        assert CANARY not in r.audit_text()


async def test_unknown_and_odd_names_are_404(tmp_path):
    async with rig(tmp_path) as r:
        for name in ["nope", "..%2Fetc", "DEMO", "a" * 40]:
            assert (await r.post(f"/api/backends/{name}/test")).status_code == 404
            assert (await r.get(f"/api/backends/{name}/impact")).status_code == 404


async def test_actions_are_audited_without_secrets(tmp_path):
    async with rig(tmp_path, secrets={"TOK": CANARY}) as r:
        await r.post("/api/backends/demo/test")
        await r.post("/api/backends/demo/restart")
        await r.post("/api/backends/demo/disable")
        events = [json.loads(line)["event"] for line in r.audit_text().splitlines() if '"admin_' in line]
        assert {"admin_backend_test", "admin_backend_restart", "admin_backend_disable"} <= set(events)
        assert CANARY not in r.audit_text()


async def test_a_change_the_reloader_refuses_is_rolled_back(tmp_path):
    async with rig(tmp_path) as r:
        before = r.file_text()

        def bad(s):
            s.backends["demo"].transport = "carrier-pigeon"
        from mcpgate.admin.session import AuthError
        with pytest.raises(AuthError):
            await r.ctx.edit(bad)
        assert r.file_text() == before and r.hub.backends["demo"].cfg.transport == "stdio"
