import json
import shlex

import pytest

from mcpgate import config as cfgmod
from tests.admin_helpers import HOST, demo, rig

CANARY = "canary-s3cr3t-7f3a91c2"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


async def test_requires_login_csrf_and_host(tmp_path):
    async with rig(tmp_path) as r:
        assert (await r.post("/api/wizard", {"done": True}, csrf=False)).status_code == 403
        assert (await r.c.get("/api/wizard", headers={"host": "evil.example"})).status_code in (400, 403, 421)
        r.c.cookies.clear()
        assert (await r.get("/api/wizard")).status_code == 401
        assert (await r.c.post("/api/wizard", headers={"host": HOST, "origin": f"http://{HOST}", "content-type": "application/json"}, content='{"done":true}')).status_code == 401


async def test_fresh_install_state_and_marking_done_and_resuming(tmp_path):
    async with rig(tmp_path, {}) as r:
        d = (await r.get("/api/wizard")).json()
        assert d["done"] is False and d["has_backend"] is False and d["summary"]["backends"] == []
        assert (await r.post("/api/wizard", {"done": True})).json() == {"done": True}
        assert (await r.get("/api/wizard")).json()["done"] is True and "wizard_done = true" in r.file_text()
        assert cfgmod.load(r.path).server.wizard_done is True
        assert (await r.post("/api/wizard", {"done": False})).json() == {"done": False}      # resumed from Settings
        assert (await r.get("/api/wizard")).json()["done"] is False


@pytest.mark.parametrize("bad", [{}, {"done": "yes"}, {"done": 1}, {"done": True, "x": 1}, {"x": True}])
async def test_bad_marks_are_refused(tmp_path, bad):
    async with rig(tmp_path) as r:
        before = r.file_text()
        assert (await r.post("/api/wizard", bad)).status_code == 400 and r.file_text() == before


async def test_connect_snippets_point_at_this_config(tmp_path):
    async with rig(tmp_path) as r:
        c = (await r.get("/api/wizard")).json()["connect"]
        assert c["command"].startswith("claude mcp add mcpgate") and c["command"].endswith("-- mcpgate serve")
        parts = shlex.split(c["command"])
        assert f"MCPGATE_CONFIG={r.path}" in parts
        snippet = json.loads(c["json"])
        assert snippet == {"mcpServers": {"mcpgate": {"command": "mcpgate", "args": ["serve"], "env": {"MCPGATE_CONFIG": str(r.path)}}}}


async def test_connect_snippet_is_plain_with_the_default_config(tmp_path, monkeypatch):
    monkeypatch.setenv("MCPGATE_CONFIG", str(tmp_path / "config.toml"))
    async with rig(tmp_path) as r:
        c = (await r.get("/api/wizard")).json()["connect"]
        assert c["command"] == "claude mcp add mcpgate -- mcpgate serve"
        assert json.loads(c["json"])["mcpServers"]["mcpgate"] == {"command": "mcpgate", "args": ["serve"]}


async def test_paths_with_spaces_and_quotes_stay_safe_in_the_command(tmp_path):
    odd = tmp_path / "my config; rm -rf x"
    odd.mkdir()
    async with rig(odd) as r:
        c = (await r.get("/api/wizard")).json()["connect"]["command"]
        assert shlex.split(c)[-3:] == ["--", "mcpgate", "serve"] and f"MCPGATE_CONFIG={r.path}" in shlex.split(c)


async def test_summary_lists_protection_and_exposure_without_any_secret_value(tmp_path):
    b = demo(confirm=["create_*"], deny=["wipe"])
    b.env = {"API_KEY": "${MY_TOKEN}"}
    async with rig(tmp_path, {"demo": b}, secrets={"MY_TOKEN": CANARY}) as r:
        await r.stepup()
        await r.post("/api/remote/passphrase", {"passphrase": "an entirely new passphrase"})
        resp = await r.get("/api/wizard")
        assert CANARY not in resp.text and "an entirely new passphrase" not in resp.text
        s = resp.json()["summary"]
        assert s["admin"]["address"].startswith("127.0.0.1:")
        assert s["backends"][0] == {"name": "demo", "transport": "stdio", "enabled": True, "needs_approval": 1, "blocked": 1,
                                    "secrets": [{"name": "MY_TOKEN", "set": True}], "connected": s["backends"][0]["connected"]}
        assert s["remote"] == {"exposed": False, "public_url": "", "signs_in": False, "token": False}
        assert s["approvals"] is False and s["audit"] is True
        await r.post("/api/remote/settings", {"public_url": "https://box.tail1234.ts.net", "oauth_enabled": True})
        assert (await r.get("/api/wizard")).json()["summary"]["remote"] == {"exposed": True, "public_url": "https://box.tail1234.ts.net", "signs_in": True, "token": False}
