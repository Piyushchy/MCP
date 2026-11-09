import json
import sys

import pytest

from mcpgate import config as cfgmod
from mcpgate.admin import addbackend
from mcpgate.config import Backend
from tests.admin_helpers import DEMO, PASS, demo, rig

CANARY = "canary-s3cr3t-7f3a91c2"
TOKEN = "ghp_" + "A" * 36


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ["GITHUB_TOKEN", "DOCS_AUTHORIZATION", "DOCS2_AUTHORIZATION"]:
        monkeypatch.delenv(name, raising=False)


def no_secret(*texts):
    for t in texts:
        assert TOKEN not in t and CANARY not in t, "a secret value leaked"


async def test_presets_shipped_are_valid():
    for p in addbackend.presets().values():
        b = Backend(name=p["name"], preset=p["id"], **json.loads(json.dumps(p["backend"])))
        b.validate()
        if b.transport != "stdio":
            cfgmod.check_backend_url(b.url)
        for f in p["fields"]:
            assert f["secret"] in b.secret_refs()


async def test_requires_login_and_csrf(tmp_path):
    async with rig(tmp_path) as r:
        for path in ["/api/backends/add", "/api/backends/preview", "/api/settings/custom-commands"]:
            assert (await r.post(path, {}, csrf=False)).status_code == 403
        r.c.cookies.clear()
        for path in ["/api/presets", "/api/settings"]:
            assert (await r.get(path)).status_code == 401


async def test_github_preset_end_to_end_secret_goes_to_store_not_config(tmp_path):
    async with rig(tmp_path, {}) as r:
        pre = (await r.get("/api/presets")).json()
        gh = next(p for p in pre["presets"] if p["id"] == "github")
        assert gh["fields"][0]["already_set"] is False and not gh["runs_program"] and pre["custom_commands"] is False
        body = {"kind": "preset", "preset": "github", "values": {"token": TOKEN}}
        view = (await r.post("/api/backends/preview", body)).json()
        assert view["target"] == "https://api.githubcopilot.com/mcp/"
        assert view["headers"] == [{"name": "Authorization", "value": "Bearer ${GITHUB_TOKEN}"}]
        assert view["secrets"] == [{"name": "GITHUB_TOKEN", "action": "store"}]
        no_secret(json.dumps(view))
        assert not r.secrets.has("GITHUB_TOKEN") and "github" not in r.hub.backends      # preview changes nothing
        assert (await r.post("/api/backends/add", body)).status_code == 400              # needs confirm
        resp = await r.post("/api/backends/add", {**body, "confirm": True})
        assert resp.status_code == 200, resp.text
        no_secret(resp.text, r.file_text(), r.audit_text())
        assert r.secrets.get("GITHUB_TOKEN") == TOKEN
        assert 'preset = "github"' in r.file_text() and "Bearer ${GITHUB_TOKEN}" in r.file_text()
        row = resp.json()["backend"]
        assert row["name"] == "github" and row["secrets"] == [{"name": "GITHUB_TOKEN", "set": True}]
        assert "github" in r.hub.backends and r.hub.backends["github"].cfg.preset == "github"
        assert (r.tmp / "secrets.json").stat().st_mode & 0o777 == 0o600


async def test_preset_token_required_unless_already_stored(tmp_path):
    async with rig(tmp_path, {}) as r:
        assert (await r.post("/api/backends/preview", {"kind": "preset", "preset": "github", "values": {}})).status_code == 400
        assert (await r.post("/api/backends/preview", {"kind": "preset", "preset": "github", "values": {"token": "has space"}})).status_code == 400
        r.secrets.set("GITHUB_TOKEN", TOKEN)
        view = (await r.post("/api/backends/preview", {"kind": "preset", "preset": "github"})).json()
        assert view["secrets"] == [{"name": "GITHUB_TOKEN", "action": "reuse"}]


@pytest.mark.parametrize("extra", [{"command": "rm"}, {"args": ["-rf"]}, {"url": "https://evil.example"}, {"env": [{"name": "A", "value": "b"}]},
                                   {"headers": []}, {"transport": "stdio"}, {"cwd": "/"}])
async def test_a_preset_cannot_be_changed_by_the_request(tmp_path, extra):
    async with rig(tmp_path, {}) as r:
        resp = await r.post("/api/backends/add", {"kind": "preset", "preset": "colab", "confirm": True, **extra})
        assert resp.status_code == 400 and "cannot be changed" in resp.json()["error"]
        assert "colab" not in r.hub.backends


async def test_colab_preset_runs_a_program_so_needs_stepup(tmp_path):
    async with rig(tmp_path, {}) as r:
        body = {"kind": "preset", "preset": "colab", "confirm": True}
        view = (await r.post("/api/backends/preview", body)).json()
        assert view["target"] == "uvx git+https://github.com/googlecolab/colab-mcp" and view["runs_program"] is True
        resp = await r.post("/api/backends/add", body)
        assert resp.status_code == 403 and resp.json()["stepup"] is True and "colab" not in r.hub.backends
        await r.stepup()
        assert (await r.post("/api/backends/add", body)).status_code == 200
        assert r.hub.backends["colab"].cfg.command == "uvx" and r.hub.backends["colab"].cfg.start_timeout == 120


async def test_unknown_preset_and_kind(tmp_path):
    async with rig(tmp_path, {}) as r:
        assert (await r.post("/api/backends/preview", {"kind": "preset", "preset": "nope"})).status_code == 400
        assert (await r.post("/api/backends/preview", {"kind": "magic"})).status_code == 400
        assert (await r.post("/api/backends/preview", {})).status_code == 400


async def test_remote_form_moves_secret_values_to_the_store(tmp_path):
    async with rig(tmp_path, {}) as r:
        body = {"kind": "remote", "name": "docs", "transport": "http", "url": "https://mcp.example.com/mcp", "start_timeout": 20,
                "description": "Docs server",
                "headers": [{"name": "Authorization", "value": "Bearer " + CANARY, "secret": True},
                            {"name": "X-Api-Key", "value": CANARY + "2"},        # not flagged, but the name says secret
                            {"name": "X-Team", "value": "blue"}]}
        view = (await r.post("/api/backends/preview", body)).json()
        assert {h["name"]: h["value"] for h in view["headers"]} == {"Authorization": "${DOCS_AUTHORIZATION}", "X-Api-Key": "${DOCS_X_API_KEY}", "X-Team": "blue"}
        no_secret(json.dumps(view))
        assert (await r.post("/api/backends/add", {**body, "confirm": True})).status_code == 200
        no_secret(r.file_text(), r.audit_text())
        assert r.secrets.get("DOCS_AUTHORIZATION") == "Bearer " + CANARY and r.secrets.get("DOCS_X_API_KEY") == CANARY + "2"
        assert "X-Team" in r.file_text() and r.hub.backends["docs"].cfg.start_timeout == 20


async def test_remote_secret_name_does_not_clobber_another_backends_secret(tmp_path):
    other = Backend(name="docs", transport="http", url="https://a.example/mcp", headers={"Authorization": "${DOCS_AUTHORIZATION}"})
    async with rig(tmp_path, {"docs": other}, secrets={"DOCS_AUTHORIZATION": "keep-me-keep-me"}) as r:
        body = {"kind": "remote", "name": "docs2", "url": "https://b.example/mcp", "headers": [{"name": "Authorization", "value": "x", "secret": True}]}
        # same generated base is only used if free: here the base is DOCS2_AUTHORIZATION, and the first backend's value is untouched
        assert (await r.post("/api/backends/add", {**body, "confirm": True})).status_code == 200
        assert r.secrets.get("DOCS_AUTHORIZATION") == "keep-me-keep-me" and r.secrets.has("DOCS2_AUTHORIZATION")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "http://example.com/mcp", "https://user:pw@example.com/",
                                 "javascript:alert(1)", "https://", "//example.com", "https://exa mple.com", "https://x.example/\nHost: evil"])
async def test_bad_urls_refused(tmp_path, url):
    async with rig(tmp_path, {}) as r:
        resp = await r.post("/api/backends/add", {"kind": "remote", "name": "x", "url": url, "confirm": True})
        assert resp.status_code == 400 and "x" not in r.hub.backends


async def test_http_allowed_for_localhost_only(tmp_path):
    async with rig(tmp_path, {}) as r:
        for url in ["http://localhost:9000/mcp", "http://127.0.0.1:9000/mcp"]:
            assert (await r.post("/api/backends/preview", {"kind": "remote", "name": "x", "url": url})).status_code == 200


@pytest.mark.parametrize("data,status", [
    ({"name": "Bad Name", "url": "https://a.example"}, 400), ({"name": "../x", "url": "https://a.example"}, 400),
    ({"name": "x", "url": "https://a.example", "transport": "ws"}, 400), ({"name": "x", "url": "https://a.example", "start_timeout": 0}, 400),
    ({"name": "x", "url": "https://a.example", "start_timeout": "soon"}, 400), ({"name": "x", "url": "https://a.example", "description": "d" * 300}, 400),
    ({"name": "x", "url": "https://a.example", "headers": "nope"}, 400),
    ({"name": "x", "url": "https://a.example", "headers": [{"name": "Bad Header", "value": "v"}]}, 400),
    ({"name": "x", "url": "https://a.example", "headers": [{"name": "X", "value": "a\r\nInjected: 1"}]}, 400),
    ({"name": "x", "url": "https://a.example", "headers": [{"name": "X", "value": "", "secret": True}]}, 400),
    ({"name": "x", "url": "https://a.example", "headers": [{"name": "X", "value": "1"}, {"name": "X", "value": "2"}]}, 400),
    ({"name": "x", "url": "https://a.example", "headers": [{"name": f"H{i}", "value": "v"} for i in range(31)]}, 400),
    ({"name": "x", "url": 5}, 400),
])
async def test_validation_errors(tmp_path, data, status):
    async with rig(tmp_path, {}) as r:
        resp = await r.post("/api/backends/preview", {"kind": "remote", **data})
        assert resp.status_code == status, resp.text
        assert "error" in resp.json()


async def test_duplicate_name_refused_including_dropins(tmp_path):
    async with rig(tmp_path) as r:
        assert (await r.post("/api/backends/preview", {"kind": "remote", "name": "demo", "url": "https://a.example"})).status_code == 409


async def test_custom_command_blocked_when_switch_off_even_via_api(tmp_path):
    async with rig(tmp_path, {}) as r:
        await r.stepup()                                          # even a fresh step-up does not help
        body = {"kind": "command", "name": "mine", "command": sys.executable, "args": [DEMO], "confirm": True}
        for path in ["/api/backends/preview", "/api/backends/add"]:
            resp = await r.post(path, body)
            assert resp.status_code == 403 and resp.json()["switch"] is True
        assert "mine" not in r.hub.backends and "mine" not in r.file_text()


async def test_existing_command_backend_cannot_be_enabled_while_switch_off(tmp_path):
    async with rig(tmp_path, {"demo": demo(enabled=False)}) as r:
        await r.stepup()
        resp = await r.post("/api/backends/demo/enable")
        assert resp.status_code == 403 and resp.json()["switch"] is True and not r.hub.backends["demo"].cfg.enabled
        assert (await r.post("/api/backends/demo/disable")).status_code == 200      # turning off is always allowed


async def test_switch_needs_stepup_and_typed_confirmation(tmp_path):
    async with rig(tmp_path, {}) as r:
        on = {"enabled": True, "confirm": "ALLOW PROGRAMS"}
        resp = await r.post("/api/settings/custom-commands", on)
        assert resp.status_code == 403 and resp.json()["stepup"] is True
        await r.stepup()
        assert (await r.post("/api/settings/custom-commands", {"enabled": True})).status_code == 400
        assert (await r.post("/api/settings/custom-commands", {"enabled": True, "confirm": "yes"})).status_code == 400
        assert (await r.post("/api/settings/custom-commands", {"enabled": "true", "confirm": "ALLOW PROGRAMS"})).status_code == 400
        assert (await r.get("/api/settings")).json() == {"custom_commands": False}
        assert (await r.post("/api/settings/custom-commands", on)).json() == {"custom_commands": True}
        assert "allow_custom_commands = true" in r.file_text()
        assert (await r.post("/api/settings/custom-commands", {"enabled": False})).json() == {"custom_commands": False}
        events = [json.loads(x)["event"] for x in r.audit_text().splitlines() if "custom_commands" in x]
        assert events == ["admin_custom_commands_on", "admin_custom_commands_off"]


async def test_custom_command_form_when_allowed(tmp_path):
    async with rig(tmp_path, {}, custom=True) as r:
        body = {"kind": "command", "name": "mine", "command": sys.executable, "args": [DEMO], "start_timeout": 20,
                "env": [{"name": "MY_API_TOKEN", "value": CANARY}, {"name": "MODE", "value": "fast"}, {"name": "HOME2", "value": "x", "secret": True}],
                "confirm": True}
        view = (await r.post("/api/backends/preview", body)).json()
        assert view["runs_program"] and view["target"] == f"{sys.executable} {DEMO}"
        assert {e["name"]: e["value"] for e in view["env"]} == {"MY_API_TOKEN": "${MINE_MY_API_TOKEN}", "MODE": "fast", "HOME2": "${MINE_HOME2}"}
        no_secret(json.dumps(view))
        assert (await r.post("/api/backends/add", body)).status_code == 403          # step-up first
        await r.stepup()
        resp = await r.post("/api/backends/add", body)
        assert resp.status_code == 200, resp.text
        no_secret(resp.text, r.file_text(), r.audit_text())
        assert r.secrets.get("MINE_MY_API_TOKEN") == CANARY
        t = (await r.post("/api/backends/mine/test")).json()
        assert t["ok"] and "echo" in t["names"]                                    # the discovered tools are returned


@pytest.mark.parametrize("data", [{"command": ""}, {"command": "a\nb"}, {"command": "x", "args": "no"}, {"command": "x", "args": ["--token=abc123"]},
                                  {"command": "x", "args": ["--api-key=abc"]}, {"command": "x", "args": [1]},
                                  {"command": "x", "env": [{"name": "1BAD", "value": "v"}]}, {"command": "x", "cwd": "a\nb"},
                                  {"command": "x", "args": ["a"] * 51}])
async def test_command_validation(tmp_path, data):
    async with rig(tmp_path, {}, custom=True) as r:
        assert (await r.post("/api/backends/preview", {"kind": "command", "name": "mine", **data})).status_code == 400


async def test_failed_save_puts_secrets_back(tmp_path, monkeypatch):
    async with rig(tmp_path, {}) as r:
        r.secrets.set("GITHUB_TOKEN", "old-old-old-old")
        from mcpgate.admin.session import AuthError

        async def broken(change):
            change(r.ctx.file_settings())
            raise AuthError(400, "that change was not applied: boom")
        monkeypatch.setattr(r.ctx, "edit", broken)
        resp = await r.post("/api/backends/add", {"kind": "preset", "preset": "github", "values": {"token": TOKEN}, "confirm": True})
        assert resp.status_code == 400 and r.secrets.get("GITHUB_TOKEN") == "old-old-old-old"
        no_secret(resp.text)


async def test_added_backend_is_audited_without_values(tmp_path):
    async with rig(tmp_path, {}) as r:
        await r.post("/api/backends/add", {"kind": "preset", "preset": "github", "values": {"token": TOKEN}, "confirm": True})
        line = next(json.loads(x) for x in r.audit_text().splitlines() if "admin_backend_add" in x)
        assert line["secrets_stored"] == ["GITHUB_TOKEN"] and line["kind"] == "preset"
        no_secret(r.audit_text())


async def test_body_must_be_json_object(tmp_path):
    async with rig(tmp_path, {}) as r:
        h = r.headers()
        assert (await r.c.post("/api/backends/preview", headers=h, content="[1,2]")).status_code == 400
        assert (await r.c.post("/api/backends/preview", headers=h, content="{nope")).status_code == 400
