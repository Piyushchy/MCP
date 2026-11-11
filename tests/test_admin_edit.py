import json

import pytest

from tests.admin_helpers import demo, rig

OLD = "ghp_" + "O" * 36
NEW = "ghp_" + "N" * 36
KEY = "key-canary-91c2f0aa"


def clean(*texts):
    for t in texts:
        assert OLD not in t and NEW not in t and KEY not in t, "a secret value leaked"


async def add_github(r):
    resp = await r.post("/api/backends/add", {"kind": "preset", "preset": "github", "values": {"token": OLD}, "confirm": True})
    assert resp.status_code == 200, resp.text


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


async def test_replacing_a_token_without_removing_the_backend(tmp_path):
    async with rig(tmp_path, {}) as r:
        await add_github(r)
        view = await r.get("/api/backends/github/edit")
        assert view.status_code == 200
        clean(view.text)
        assert view.json()["secrets"] == [{"name": "GITHUB_TOKEN", "set": True}] and view.json()["editable"] == ["description", "set_secrets"]
        resp = await r.post("/api/backends/github/edit", {"set_secrets": {"GITHUB_TOKEN": NEW}})
        assert resp.status_code == 200, resp.text
        assert r.secrets.get("GITHUB_TOKEN") == NEW and "github" in r.hub.backends
        clean(resp.text, r.file_text(), r.audit_text(), (await r.get("/api/backends")).text, (await r.get("/api/secrets")).text)
        assert "admin_backend_edit" in r.audit_text()


async def test_only_secrets_the_backend_uses_can_be_set_and_presets_stay_locked(tmp_path):
    async with rig(tmp_path, {}) as r:
        await add_github(r)
        assert (await r.post("/api/backends/github/edit", {"set_secrets": {"OTHER": NEW}})).status_code == 400
        assert (await r.post("/api/backends/github/edit", {"set_secrets": {"GITHUB_TOKEN": "  "}})).status_code == 400
        for bad in ({"url": "https://evil.example/"}, {"command": "sh"}, {"headers": []}, {"start_timeout": 5}, {"nonsense": 1}):
            assert (await r.post("/api/backends/github/edit", bad)).status_code == 400, bad
        assert (await r.post("/api/backends/github/edit", {"description": "work repos"})).status_code == 200
        assert r.hub.backends["github"].cfg.description == "work repos"
        assert r.secrets.get("GITHUB_TOKEN") == OLD
        assert (await r.post("/api/backends/nope/edit", {})).status_code == 404


async def test_editing_a_remote_backend_adds_a_secret_header_and_keeps_existing_ones(tmp_path):
    async with rig(tmp_path, {}) as r:
        resp = await r.post("/api/backends/add", {"kind": "remote", "name": "docs", "url": "https://docs.example.com/mcp", "confirm": True,
                                                  "headers": [{"name": "X-Team", "value": "blue"}]})
        assert resp.status_code == 200, resp.text
        body = {"url": "https://docs.example.com/v2/mcp", "description": "docs",
                "headers": [{"name": "X-Team", "value": "blue"}, {"name": "X-Api-Key", "value": KEY, "secret": True}]}
        resp = await r.post("/api/backends/docs/edit", body)
        assert resp.status_code == 200, resp.text
        cfg = r.hub.backends["docs"].cfg
        assert cfg.url.endswith("/v2/mcp") and cfg.headers["X-Api-Key"] == "${DOCS_X_API_KEY}" and r.secrets.get("DOCS_X_API_KEY") == KEY
        clean(resp.text, r.file_text(), r.audit_text())
        view = (await r.get("/api/backends/docs/edit")).json()
        assert {"name": "X-Api-Key", "value": "", "secret": "DOCS_X_API_KEY", "set": True} in view["headers"]
        # keep the stored secret, replace its value, and drop the plain header
        again = {"headers": [{"name": "X-Api-Key", "secret": "DOCS_X_API_KEY"}], "set_secrets": {"DOCS_X_API_KEY": NEW}}
        assert (await r.post("/api/backends/docs/edit", again)).status_code == 200
        assert r.secrets.get("DOCS_X_API_KEY") == NEW and list(r.hub.backends["docs"].cfg.headers) == ["X-Api-Key"]
        # a refused change leaves the stored values as they were
        assert (await r.post("/api/backends/docs/edit", {"url": "http://evil.example/", "set_secrets": {"DOCS_X_API_KEY": OLD}})).status_code == 400
        assert r.secrets.get("DOCS_X_API_KEY") == NEW
        assert (await r.post("/api/backends/docs/edit", {"command": "sh"})).status_code == 400   # a remote backend has no command


async def test_changing_a_program_needs_the_passphrase_again_but_renaming_does_not(tmp_path):
    async with rig(tmp_path, {"demo": demo()}, custom=True) as r:
        assert (await r.post("/api/backends/demo/edit", {"description": "notes"})).status_code == 200
        resp = await r.post("/api/backends/demo/edit", {"args": ["-u", *r.hub.backends["demo"].cfg.args]})
        assert resp.status_code == 403 and resp.json()["stepup"] is True
        assert r.hub.backends["demo"].cfg.args == demo().args
        await r.stepup()
        assert (await r.post("/api/backends/demo/edit", {"args": ["-u", *r.hub.backends["demo"].cfg.args]})).status_code == 200
        assert r.hub.backends["demo"].cfg.args[0] == "-u"
        assert (await r.post("/api/backends/demo/edit", {"args": ["x", "token=abc123"]})).status_code == 400
    async with rig(tmp_path / "off", {"demo": demo()}, custom=False) as r2:
        (tmp_path / "off").mkdir(exist_ok=True)
        await r2.stepup()
        resp = await r2.post("/api/backends/demo/edit", {"command": "python3"})
        assert resp.status_code == 403 and resp.json().get("switch") is True


async def test_edit_endpoints_need_login_and_csrf(tmp_path):
    async with rig(tmp_path, {"demo": demo()}) as r:
        assert (await r.post("/api/backends/demo/edit", {}, csrf=False)).status_code == 403
        assert (await r.post("/api/secrets/X", {"value": "abcdef"}, csrf=False)).status_code == 403
        r.c.cookies.clear()
        assert (await r.get("/api/backends/demo/edit")).status_code == 401
        assert (await r.get("/api/secrets")).status_code == 401


async def test_secrets_page_lists_uses_and_sets_and_deletes_without_showing_values(tmp_path):
    async with rig(tmp_path, {}) as r:
        await add_github(r)
        r.secrets.set("UNUSED_ONE", KEY)
        listing = (await r.get("/api/secrets")).json()["secrets"]
        clean(json.dumps(listing))
        by = {s["name"]: s for s in listing}
        assert by["GITHUB_TOKEN"]["used_by"] == ["github"] and by["UNUSED_ONE"]["used_by"] == [] and all(s["set"] for s in listing)
        assert (await r.post("/api/secrets/bad-name", {"value": "abcdef"})).status_code == 400
        assert (await r.post("/api/secrets/GITHUB_TOKEN", {"value": ""})).status_code == 400
        resp = await r.post("/api/secrets/GITHUB_TOKEN", {"value": NEW})
        assert resp.status_code == 200 and set(resp.json()["restarted"]) <= {"github"}
        assert r.secrets.get("GITHUB_TOKEN") == NEW
        assert (await r.post("/api/secrets/UNUSED_ONE/delete", {})).status_code == 400
        assert (await r.post("/api/secrets/UNUSED_ONE/delete", {"confirm": True})).status_code == 200
        assert not r.secrets.has("UNUSED_ONE") and (await r.post("/api/secrets/UNUSED_ONE/delete", {"confirm": True})).status_code == 404
        # a secret a backend refers to but nobody has stored shows up as missing
        r.secrets.delete("GITHUB_TOKEN")
        missing = {s["name"]: s for s in (await r.get("/api/secrets")).json()["secrets"]}
        assert missing["GITHUB_TOKEN"]["set"] is False and missing["GITHUB_TOKEN"]["used_by"] == ["github"]
        clean(r.audit_text(), r.file_text())
        events = [json.loads(x)["event"] for x in r.audit_text().splitlines() if "admin_secret" in x]
        assert events == ["admin_secret_set", "admin_secret_delete"]
