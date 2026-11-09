import json
import re
from pathlib import Path

from mcpgate import config as cfgmod
from mcpgate.backends import ToolInfo
from mcpgate.config import Backend
from tests.admin_helpers import PASS, demo, rig

STATIC = Path(__file__).parent.parent / "mcpgate" / "admin" / "static"


async def load(r, name="demo"):
    resp = await r.post(f"/api/backends/{name}/policy/load")
    assert resp.status_code == 200, resp.text
    return resp.json()


def states(p):
    return {t["name"]: t["state"] for t in p["tools"]}


async def test_requires_login_and_csrf_and_valid_names(tmp_path):
    async with rig(tmp_path) as r:
        for action in ["load", "preview", "save"]:
            assert (await r.post(f"/api/backends/demo/policy/{action}", csrf=False)).status_code == 403
        for name in ["nope", "..%2Fx"]:
            assert (await r.get(f"/api/backends/{name}/policy")).status_code == 404
            assert (await r.post(f"/api/backends/{name}/policy/load")).status_code == 404
        r.c.cookies.clear()
        assert (await r.get("/api/backends/demo/policy")).status_code == 401


async def test_not_loaded_shows_saved_rules_but_is_not_editable(tmp_path):
    async with rig(tmp_path, {"demo": demo(deny=["delete_*"])}) as r:
        p = (await r.get("/api/backends/demo/policy")).json()
        assert p["loaded"] is False and p["editable"] is False and "not loaded" in p["why"]
        assert p["rules"]["deny"] == ["delete_*"] and p["tools"] == []
        assert (await r.post("/api/backends/demo/policy/save", {"changes": {}})).status_code == 409


async def test_load_lists_real_tools_with_hints(tmp_path):
    async with rig(tmp_path) as r:
        p = await load(r)
        assert p["editable"] and p["loaded"]
        by = {t["name"]: t for t in p["tools"]}
        assert by["wipe"]["destructive"] and by["wipe"]["state"] == "confirm" and "destructive" in by["wipe"]["reason"]
        assert by["wipe"]["options"]["allow"] and by["echo"]["options"] == {"allow": None, "confirm": None, "block": None}
        assert any(t["read_only"] for t in p["tools"]) and by["echo"]["description"]


async def test_save_takes_effect_and_matches_what_the_model_sees(tmp_path):
    async with rig(tmp_path) as r:
        await load(r)
        resp = await r.post("/api/backends/demo/policy/save", {"changes": {"echo": "block", "add": "confirm"}})
        assert resp.status_code == 200, resp.text
        p = resp.json()
        assert states(p)["echo"] == "block" and states(p)["add"] == "confirm"
        text = r.file_text()
        assert 'deny = [\n    "echo"' in text.replace("[ ", "[\n    ") or '"echo"' in text
        # the gateway itself now agrees, on the next call, with no restart
        tools, _ = await r.hub.catalog("demo")
        assert sorted(t.name for t in tools) == sorted(p["model_sees"]) and "echo" not in p["model_sees"]
        assert r.hub.policies["demo"].needs_confirm("add") and not r.hub.policies["demo"].needs_confirm("counter")
        assert set(p["needs_approval"]) >= {"add", "wipe"} and p["hidden"] == ["echo"]


async def test_handwritten_globs_survive_a_save(tmp_path):
    async with rig(tmp_path, {"demo": demo(deny=["delete_*", "die"], confirm=["create_*"])}) as r:
        p = await load(r)
        assert states(p)["delete_note"] == "block" and "delete_*" in p["tools"][0]["reason"] + str([t["reason"] for t in p["tools"]])
        p = (await r.post("/api/backends/demo/policy/save", {"changes": {"echo": "block"}})).json()
        assert p["rules"] == {"allow": ["*"], "deny": ["delete_*", "die", "echo"], "confirm": ["create_*"]}
        s = cfgmod.load(r.path).backends["demo"]
        assert s.deny == ["delete_*", "die", "echo"] and s.confirm == ["create_*"]


async def test_glob_conflict_is_explained_and_removing_the_pattern_resolves_it(tmp_path):
    async with rig(tmp_path, {"demo": demo(deny=["delete_*"])}) as r:
        await load(r)
        resp = await r.post("/api/backends/demo/policy/save", {"changes": {"delete_note": "allow"}})
        assert resp.status_code == 409 and 'deny pattern "delete_*"' in resp.json()["error"]
        assert cfgmod.load(r.path).backends["demo"].deny == ["delete_*"]
        resp = await r.post("/api/backends/demo/policy/save", {"changes": {"delete_note": "allow"}, "remove": {"deny": ["delete_*"]}})
        assert resp.status_code == 200 and states(resp.json())["delete_note"] == "allow"
        assert cfgmod.load(r.path).backends["demo"].deny == []


async def test_displayed_state_follows_deny_wins_over_allow(tmp_path):
    async with rig(tmp_path, {"demo": demo(allow=["echo", "add"], deny=["echo"])}) as r:
        p = await load(r)
        assert states(p)["echo"] == "block" and states(p)["add"] == "allow" and states(p)["counter"] == "block"
        tools, _ = await r.hub.catalog("demo")
        assert [t.name for t in tools] == ["add"] == p["model_sees"]


async def test_preview_writes_nothing(tmp_path):
    async with rig(tmp_path) as r:
        await load(r)
        before = r.file_text()
        p = (await r.post("/api/backends/demo/policy/preview", {"changes": {"echo": "block"}})).json()
        assert states(p)["echo"] == "block" and "echo" not in p["model_sees"]
        assert r.file_text() == before and not r.hub.policies["demo"].deny
        assert (await r.get("/api/backends/demo/policy")).json()["rules"]["deny"] == []


async def test_bad_requests(tmp_path):
    async with rig(tmp_path) as r:
        await load(r)
        for data in [{"changes": {"echo": "maybe"}}, {"changes": {"no_such_tool": "block"}}, {"changes": []}, {"remove": {"deny": ["x"]}},
                     {"remove": {"other": []}}, {"remove": {"deny": "x"}}, {"changes": {f"t{i}": "block" for i in range(501)}}]:
            assert (await r.post("/api/backends/demo/policy/save", data)).status_code == 400, data
        assert cfgmod.load(r.path).backends["demo"].deny == []


async def test_unreachable_backend_shows_rules_but_cannot_be_edited(tmp_path):
    bad = Backend(name="broken", transport="stdio", command="/nonexistent/prog", deny=["x_*"], start_timeout=3)
    async with rig(tmp_path, {"broken": bad}) as r:
        p = await load(r, "broken")
        assert p["editable"] is False and p["rules"]["deny"] == ["x_*"] and p["why"]
        assert (await r.post("/api/backends/broken/policy/save", {"changes": {}})).status_code == 409


async def test_went_down_after_loading_is_also_not_editable(tmp_path):
    async with rig(tmp_path) as r:
        await load(r)
        b = r.hub.backends["demo"]
        await b.stop()
        b.error = "connection lost"
        p = (await r.get("/api/backends/demo/policy")).json()
        assert p["editable"] is False and "cannot be reached" in p["why"]


async def test_disabled_backend_cannot_be_edited(tmp_path):
    async with rig(tmp_path, {"off": demo("off", enabled=False)}) as r:
        p = await load(r, "off")
        assert not p["editable"] and "disabled" in p["why"]


async def test_dropin_policy_is_read_only(tmp_path):
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / "notes.py").write_text('"""My notes."""\nfrom mcp.server.fastmcp import FastMCP\nFastMCP("notes").run()\n')
    async with rig(tmp_path) as r:
        s = cfgmod.load(r.path)
        s.custom_dir = str(custom)
        cfgmod.save(s, r.path)
        await r.ctx.reloader.check(force=True)
        p = await load(r, "notes")
        assert not p["editable"] and "drop-in" in p["why"]


async def test_changed_on_disk_meanwhile_is_refused(tmp_path):
    async with rig(tmp_path) as r:
        await load(r)
        s = cfgmod.load(r.path)
        s.backends["demo"].deny = ["something"]
        cfgmod.save(s, r.path)                                   # edited by hand; the gateway has not reloaded yet
        resp = await r.post("/api/backends/demo/policy/save", {"changes": {"echo": "block"}})
        assert resp.status_code == 409 and "changed on disk" in resp.json()["error"]
        assert cfgmod.load(r.path).backends["demo"].deny == ["something"]


async def test_hostile_tool_text_is_only_ever_data(tmp_path):
    async with rig(tmp_path) as r:
        await load(r)
        b = r.hub.backends["demo"]
        evil = "<img src=x onerror=alert(1)>"
        b._tools = [ToolInfo("demo", evil, evil + "\n" + "x" * 1000, {}, False, False)]
        resp = await r.get("/api/backends/demo/policy")
        assert resp.headers["content-type"].startswith("application/json")
        t = resp.json()["tools"][0]
        assert t["name"] == evil and t["description"] == evil and "\n" not in t["description"]
        b._tools = [ToolInfo("demo", "ok", "y" * 1000, {}, False, False)]
        assert len((await r.get("/api/backends/demo/policy")).json()["tools"][0]["description"]) <= 301
    js = (STATIC / "app.js").read_text()
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "outerHTML" not in js


async def test_policy_changes_are_audited(tmp_path):
    async with rig(tmp_path) as r:
        await load(r)
        await r.post("/api/backends/demo/policy/save", {"changes": {"echo": "block"}})
        ev = next(json.loads(x) for x in r.audit_text().splitlines() if "admin_policy_change" in x)
        assert ev["backend"] == "demo" and ev["changes"] == {"echo": "block"}
