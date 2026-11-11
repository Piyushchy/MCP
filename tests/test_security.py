"""The security rules of the admin UI, proved. Each test names the rule it guards (see SECURITY.md).

1 loopback only   2 public listener has no admin code   3 secrets are write-only   4 session + CSRF + Origin + Host
5 code-running actions need step-up   6 strict CSP, no inline script   7 private files   8 every route is tested"""
import inspect
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from starlette.routing import Route

from mcpgate import cli, serve, server
from mcpgate.admin import app as admin
from mcpgate.config import Backend, Settings
from tests.admin_helpers import DEMO, HOST, PASS, PORT, demo, rig

CANARY = "canary-s3cr3t-9d41c7e0"
EVIL = "<img src=x onerror=alert(1)><script>alert(2)</script>\"'`"
PUBLIC_GETS = {"/", "/static/app.js", "/static/app.css", "/api/health", "/api/session"}
STATIC = Path(admin.__file__).parent / "static"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for k in ("GITHUB_TOKEN", "MCPGATE_TOKEN", "MCPGATE_PASSPHRASE", "INVOCATION_ID", "MCPGATE_SUPERVISED"):
        monkeypatch.delenv(k, raising=False)


def fill(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


def specs_of(r):
    return admin.make_app(PORT, auth=r.auth, ctx=r.ctx).app.state.specs


# ===== rule 8: the route table ==================================================================================
async def test_route_table_has_no_unprotected_route_and_no_route_outside_it(tmp_path):
    async with rig(tmp_path) as r:
        built = admin.make_app(PORT, auth=r.auth, ctx=r.ctx)
        specs = built.app.state.specs
        seen = set()
        for s in specs:
            assert set(s.methods) <= {"GET", "POST"}, s.path
            for m in s.methods:
                assert (s.path, m) not in seen, f"{m} {s.path} is declared twice"
                seen.add((s.path, m))
            if s.state_changing:
                assert s.path in admin.PRE_AUTH or (s.session and s.csrf), f"POST {s.path} needs a session and CSRF"
            else:
                assert s.session or s.path in PUBLIC_GETS, f"GET {s.path} is open to anyone; add it to PUBLIC_GETS only if that is intended"
        # nothing is mounted that the table does not know about
        assert {x.path for x in built.app.routes if isinstance(x, Route)} == {s.path for s in specs}
        assert len(built.app.routes) == len(specs)           # one Starlette route per Spec, nothing extra mounted
        assert admin.PRE_AUTH == {"/api/setup", "/api/login"}


async def test_every_route_refuses_the_wrong_caller(tmp_path):
    async with rig(tmp_path) as r:
        specs = specs_of(r)
        assert len(specs) > 40
        headers_seen = []
        for s in specs:
            url = fill(s.path)
            for m in s.methods:
                body = {} if m == "POST" else None
                # a foreign Host or any proxy header: refused everywhere, even the health check and the page
                for extra in ({"host": "evil.example"}, {"host": "evil.example:8767"}, {"x-forwarded-for": "1.2.3.4"}, {"x-forwarded-host": "evil.example"},
                              {"forwarded": "for=1.2.3.4"}, {"via": "1.1 proxy"}, {"cf-connecting-ip": "1.2.3.4"}, {"tailscale-user-login": "a@b.c"}):
                    h = {**r.headers(), **extra}
                    resp = await r.c.request(m, url, headers=h, content=json.dumps(body) if body is not None else None)
                    assert 400 <= resp.status_code < 500, (m, s.path, extra, resp.status_code)
                    headers_seen.append(resp.headers)
                if m == "POST" and s.path not in admin.PRE_AUTH:
                    # a logged-in browser tab of another site: right cookie, wrong or missing Origin / CSRF token
                    for h in ({**r.headers(), "origin": "http://evil.example"}, {**r.headers(), "origin": "null"}, {**r.headers(), "origin": f"https://{HOST}"},
                              r.headers(csrf=False), {**r.headers(), "x-csrf-token": "x" * 40}):
                        h = {k: v for k, v in h.items()}
                        resp = await r.c.post(url, headers=h, content="{}")
                        assert resp.status_code == 403, (s.path, h.get("origin"), resp.status_code)
                        headers_seen.append(resp.headers)
                if m == "POST":
                    no_origin = {k: v for k, v in r.headers().items() if k != "origin"}
                    assert (await r.c.post(url, headers=no_origin, content="{}")).status_code in (400, 403), s.path
        # clickjacking, sniffing and caching headers are on every one of those error responses too
        for h in headers_seen:
            assert h["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in h["content-security-policy"]
            assert h["x-content-type-options"] == "nosniff" and h["cache-control"] == "no-store"


async def test_without_a_session_nothing_is_served_except_the_shell(tmp_path):
    async with rig(tmp_path) as r:
        specs = specs_of(r)
        r.c.cookies.clear()
        for s in specs:
            for m in s.methods:
                h = {"host": HOST, "origin": f"http://{HOST}", "content-type": "application/json", "x-csrf-token": r.csrf}
                resp = await r.c.request(m, fill(s.path), headers=h, content="{}" if m == "POST" else None)
                if m == "GET" and s.path in PUBLIC_GETS:
                    assert resp.status_code == 200, s.path
                elif s.path in admin.PRE_AUTH:
                    assert resp.status_code in (400, 401, 403, 409, 429), s.path        # needs a credential in the body
                else:
                    assert resp.status_code == 401, (m, s.path, resp.status_code)
                assert PASS not in resp.text


# ===== rule 1: loopback only, no way to change it =================================================================
def test_the_admin_bind_address_cannot_be_configured():
    assert admin.ADMIN_HOST == "127.0.0.1"
    assert list(inspect.signature(admin.bind).parameters) == ["port"]
    assert list(inspect.signature(admin.AdminServer.__init__).parameters) == ["self", "port", "extra", "auth", "ctx"]
    options = {o for a in cli.parser()._subparsers._group_actions[0].choices.values() for act in a._actions for o in act.option_strings}
    assert not {o for o in options if "admin" in o and ("host" in o or "bind" in o or "listen" in o)}
    # no setting or environment variable can name another address for it
    from dataclasses import fields

    from mcpgate.config import Server
    assert not [f.name for f in fields(Server) if re.search(r"admin.*(host|bind|listen|addr)|(bind|listen)", f.name)]
    code = "".join(p.read_text() for p in Path(admin.__file__).parent.glob("*.py"))
    assert not re.search(r"(environ|getenv)[^\n]*(ADMIN|BIND|LISTEN)", code, re.I)
    assigned = [a.split("#")[0].strip() for a in re.findall(r"^ADMIN_HOST\s*=.*$", code, re.M)]
    assert assigned == ['ADMIN_HOST = "127.0.0.1"'], assigned


def test_binding_somewhere_else_is_not_an_option_and_a_busy_port_does_not_fall_back():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    port = s.getsockname()[1]
    try:
        with pytest.raises(admin.AdminError, match="will not start elsewhere"):
            admin.bind(port)
    finally:
        s.close()
    ok = admin.bind(port)
    assert ok.getsockname()[0] == "127.0.0.1"
    ok.close()


# ===== rule 2: the public listener has no admin code ==================================================================
async def test_every_admin_path_is_absent_from_the_public_listener(tmp_path):
    async with rig(tmp_path) as r:
        paths = sorted({fill(s.path) for s in specs_of(r)})
    app, _ = server.build(Settings())
    for asgi in (serve.make_http_server(app, "127.0.0.1", 0, "t" * 32).config.app, serve.make_http_server(app, "127.0.0.1", 0, None).config.app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=asgi), base_url="http://127.0.0.1:8766") as c:
            for path in paths:
                for headers in ({}, {"authorization": "Bearer " + "t" * 32}):
                    for method in ("GET", "POST"):
                        resp = await c.request(method, path, headers={**headers, "host": "127.0.0.1:8766"}, content="{}" if method == "POST" else None)
                        assert resp.status_code in (401, 404, 405, 406, 400), (method, path, resp.status_code)
                        assert "mcpgate admin" not in resp.text and "csrf" not in resp.text.lower()


def test_the_public_modules_do_not_import_the_admin_code():
    root = Path(serve.__file__).parent
    for name in ("serve.py", "server.py", "hub.py", "oauth.py", "backends.py"):
        text = (root / name).read_text()
        assert not re.search(r"^\s*(from|import)\s+\.?admin|from \.admin|from mcpgate\.admin", text, re.M), name


# ===== rule 4: sessions =================================================================================================
async def test_a_session_id_set_by_an_attacker_is_never_adopted(tmp_path):
    async with rig(tmp_path) as r:
        r.c.cookies.clear()
        h = {"host": HOST, "origin": f"http://{HOST}", "content-type": "application/json"}
        r.c.cookies.set("mcpgate_admin", "attacker-chosen-value", domain="127.0.0.1")
        resp = await r.c.post("/api/login", headers=h, content=json.dumps({"passphrase": PASS}))
        assert resp.status_code == 200
        cookie = resp.headers["set-cookie"]
        assert "attacker-chosen-value" not in cookie and "httponly" in cookie.lower() and "samesite=strict" in cookie.lower()
        r.c.cookies.clear()
        r.c.cookies.set("mcpgate_admin", "attacker-chosen-value", domain="127.0.0.1")
        assert (await r.get("/api/session")).json().get("state") != "signed_in"


async def test_passphrase_change_and_logout_end_old_sessions(tmp_path):
    async with rig(tmp_path) as r:
        old = r.c.cookies.get("mcpgate_admin")
        assert old
        await r.stepup()
        assert (await r.post("/api/passphrase", {"current": PASS, "new": "an entirely new admin passphrase"})).status_code == 200
        assert r.c.cookies.get("mcpgate_admin") != old
        r.c.cookies.set("mcpgate_admin", old, domain="127.0.0.1")
        assert (await r.get("/api/backends")).status_code == 401


# ===== rule 5: code-running actions need step-up =========================================================================
async def test_every_action_that_can_run_code_or_open_access_needs_the_passphrase_again(tmp_path):
    """(The off-switch for custom commands is a second lock in front of the add; here it is open so step-up is what is tested.)"""
    custom = {"kind": "command", "name": "mine", "command": sys.executable, "args": [DEMO], "confirm": True}
    async with rig(tmp_path, {"demo": demo(), "off": Backend(name="off", transport="stdio", command=sys.executable, args=[DEMO], enabled=False)}, custom=True) as r:
        gated = [("/api/backends/add", custom),
                 ("/api/backends/off/enable", {}), ("/api/remote/passphrase", {"passphrase": "an entirely new passphrase"}), ("/api/remote/token", {}),
                 ("/api/remote/restart", {})]
        for path, data in gated:
            resp = await r.post(path, data)
            assert resp.status_code == 403 and resp.json().get("stepup") is True, (path, resp.status_code, resp.text)
        assert "mine" not in r.hub.settings.backends and r.hub.settings.backends["off"].enabled is False
    async with rig(tmp_path / "b", {"demo": demo()}) as r:                               # the switch itself is gated too
        (tmp_path / "b").mkdir(exist_ok=True)
        resp = await r.post("/api/settings/custom-commands", {"enabled": True})
        assert resp.status_code == 403 and resp.json().get("stepup") is True and r.ctx.file_settings().server.allow_custom_commands is False


async def test_changing_the_admin_passphrase_needs_the_current_one(tmp_path):
    async with rig(tmp_path) as r:
        resp = await r.post("/api/passphrase", {"current": "wrong-" + CANARY, "new": "an entirely new admin passphrase"})
        assert resp.status_code in (401, 403) and CANARY not in resp.text
        assert (await r.post("/api/passphrase", {"new": "an entirely new admin passphrase"})).status_code in (400, 401)


# ===== rule 6: strict CSP, no inline script ==================================================================================
def test_content_security_policy_and_frontend_sinks():
    csp = admin.SECURITY_HEADERS["content-security-policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0] and "'unsafe-eval'" not in csp
    assert "default-src 'none'" in csp                       # so objects, frames, workers and media are all off unless listed
    assert "frame-ancestors 'none'" in csp and "base-uri 'none'" in csp and "form-action 'self'" in csp and "object-src" not in csp.replace("object-src 'none'", "")
    assert not re.search(r"https?://", csp.replace("http://127.0.0.1", ""))
    js = (STATIC / "app.js").read_text()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\"", "setInterval(\"", "srcdoc", "javascript:"):
        assert sink not in js, f"{sink} would let a hostile value run as code"
    assert not re.search(r"setAttribute\(\s*[\"']on", js) and not re.search(r"\bon[a-z]+\s*:\s*[\"']", js)
    html = (STATIC / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html) and not re.search(r"\son[a-z]+\s*=", html) and not re.search(r"https?://", html)


async def test_hostile_values_come_back_only_as_json_data(tmp_path):
    """Anything a backend, an app or a client can name is returned inside JSON with nosniff, never as markup."""
    from mcp.shared.auth import OAuthClientInformationFull

    from mcpgate.oauth import GatewayOAuth
    b = demo(description=EVIL)
    async with rig(tmp_path, {"demo": b}) as r:
        prov = GatewayOAuth("https://box.example.com", passphrase=PASS, state_path=r.tmp / "oauth.json")
        client = OAuthClientInformationFull(client_id="c1", client_name=EVIL, redirect_uris=["https://claude.ai/cb"], token_endpoint_auth_method="none")
        await prov.register_client(client)
        prov._issue("c1", [], None)
        await r.hub.call("demo.echo", {"text": EVIL})
        r.hub.audit.log(event="admin_x", tool="demo." + EVIL, args={"k": EVIL}, status=EVIL)
        for path in ("/api/backends", "/api/remote", "/api/audit", "/api/wizard", "/api/approvals"):
            resp = await r.get(path)
            assert resp.status_code == 200, path
            assert resp.headers["content-type"].startswith("application/json") and resp.headers["x-content-type-options"] == "nosniff", path
            assert not resp.text.lstrip().startswith("<")
        assert EVIL in (await r.get("/api/remote")).json()["clients"][0]["name"]
        assert (await r.get("/api/audit")).json()["entries"][0]["tool"] == "demo." + EVIL


# ===== rule 3: secrets are write-only ===================================================================================
async def test_a_canary_secret_never_appears_anywhere_it_could_be_read(tmp_path, capfd, caplog):
    caplog.set_level(0)
    b = demo(env={"API_KEY": "${CANARY_TOKEN}"})
    async with rig(tmp_path, {"demo": b}, secrets={"CANARY_TOKEN": CANARY}) as r:
        seen = []

        async def grab(resp):
            seen.append((str(resp.url), resp.text, dict(resp.headers)))
            return resp
        await r.stepup()
        # read everything the page can read
        for s in specs_of(r):
            if s.methods == ("GET",) and "{" not in s.path:
                await grab(await r.get(s.path))
        await grab(await r.get("/api/backends/demo/policy"))
        # actions with the canary in every place a person could type it
        add = {"kind": "remote", "name": "docs", "transport": "http", "url": "https://mcp.example.com/mcp", "start_timeout": 5, "description": "d",
               "headers": [{"name": "Authorization", "value": "Bearer " + CANARY + "-new", "secret": True}], "confirm": True}
        await grab(await r.post("/api/backends/preview", add))
        await grab(await r.post("/api/backends/add", add))
        await grab(await r.post("/api/backends/demo/test"))
        await grab(await r.post("/api/backends/docs/test"))
        await grab(await r.post("/api/backends/demo/policy/load", {}))
        await grab(await r.post("/api/backends/docs/remove", {"confirm": True, "delete_secrets": True}))
        await grab(await r.post("/api/remote/passphrase", {"passphrase": "pw " + CANARY}))
        token = (await r.post("/api/remote/token")).json()["token"]
        await grab(await r.get("/api/remote"))
        # the model's side: the text of an error is scrubbed. (Results that a backend itself returns are passed on as they are.)
        try:
            await r.hub.call("demo.nosuchtool", {"text": CANARY})
        except Exception as e:  # noqa: BLE001 - the text a model would be shown
            seen.append(("tool error", str(e), {}))
        out = capfd.readouterr()
        everything = "\n".join(f"{u}\n{t}\n{h}" for u, t, h in seen) + r.audit_text() + out.out + out.err + caplog.text
        assert CANARY not in everything
        assert token not in r.audit_text() and token not in (await r.get("/api/remote")).text
        assert "pw " + CANARY not in everything
        # the stored copy is the only place it lives, and it is private
        assert CANARY in (r.tmp / "secrets.json").read_text()
        assert stat.S_IMODE((r.tmp / "secrets.json").stat().st_mode) == 0o600


def test_doctor_never_prints_a_stored_secret(tmp_path):
    cfgdir = tmp_path / "mcpgate"
    cfgdir.mkdir(mode=0o700)
    from mcpgate import config as cfgmod
    from mcpgate.secretstore import SecretStore
    s = Settings(backends={"demo": demo(env={"API_KEY": "${CANARY_TOKEN}"})})
    cfgmod.save(s, cfgdir / "config.toml")
    SecretStore(cfgdir / "secrets.json").set("CANARY_TOKEN", CANARY)
    env = {"HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path), "XDG_STATE_HOME": str(tmp_path / "state"), "PATH": "/usr/bin:/bin"}
    for extra in ([], ["--no-connect"]):
        p = subprocess.run([sys.executable, "-m", "mcpgate", "doctor", *extra], env={**env, "PYTHONPATH": str(Path(cli.__file__).parent.parent)},
                           capture_output=True, text=True, timeout=120)
        assert CANARY not in p.stdout + p.stderr and "CANARY_TOKEN" in p.stdout
    p = subprocess.run([sys.executable, "-m", "mcpgate", "secret", "list"], env={**env, "PYTHONPATH": str(Path(cli.__file__).parent.parent)}, capture_output=True, text=True)
    assert CANARY not in p.stdout + p.stderr and "CANARY_TOKEN" in p.stdout


# ===== rule 7: private files ================================================================================================
def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


async def test_every_file_that_holds_a_secret_or_a_hash_is_owner_only(tmp_path):
    from mcp.shared.auth import OAuthClientInformationFull

    from mcpgate.oauth import GatewayOAuth
    cfg = tmp_path / "newroot" / "mcpgate"                   # created fresh: mode of the folder matters too
    cfg.parent.mkdir()
    async with rig(cfg) as r:
        r.secrets.set("SOME_TOKEN", "some-long-token-value")
        await r.stepup()
        await r.post("/api/remote/passphrase", {"passphrase": "an entirely new passphrase"})
        await r.post("/api/remote/token")
        prov = GatewayOAuth("https://box.example.com", passphrase=PASS, state_path=cfg / "oauth.json")
        client = OAuthClientInformationFull(client_id="c1", client_name="x", redirect_uris=["https://claude.ai/cb"], token_endpoint_auth_method="none")
        await prov.register_client(client)
        prov._issue("c1", [], None)
        await r.post("/api/audit/settings", {"max_mb": 1})
        r.hub.audit.max_bytes = 600
        for i in range(30):
            r.hub.audit.log(n=i, pad="x" * 40)
        files = [f for f in cfg.iterdir() if f.is_file()]
        names = {f.name for f in files}
        assert {"config.toml", "secrets.json", "auth.json", "oauth.json", "audit.jsonl", "audit.jsonl.1"} <= names, names
        for f in files:
            assert mode(f) & 0o077 == 0, f"{f.name} is {oct(mode(f))}"
        assert not [n for n in names if n.endswith(".tmp")], "no half-written temp files are left behind"
        assert mode(cfg) == 0o700, oct(mode(cfg))


def test_group_readable_secret_and_auth_files_are_refused(tmp_path):
    from mcpgate.authstore import AuthStore
    from mcpgate.config import ConfigError
    from mcpgate.secretstore import SecretStore
    s = SecretStore(tmp_path / "secrets.json")
    s.set("A_SECRET", "value-value")
    a = AuthStore(tmp_path / "auth.json")
    a.set_token("static_token", "t" * 40)
    for f in (tmp_path / "secrets.json", tmp_path / "auth.json"):
        f.chmod(0o640)
    with pytest.raises(ConfigError, match="chmod 600"):
        SecretStore(tmp_path / "secrets.json").names()
    with pytest.raises(ConfigError, match="chmod 600"):
        AuthStore(tmp_path / "auth.json").has("static_token")


def test_doctor_flags_every_private_file_that_others_can_read(tmp_path):
    from mcpgate import config as cfgmod
    from mcpgate.authstore import AuthStore
    from mcpgate.secretstore import SecretStore
    d = tmp_path / "mcpgate"
    cfgmod.save(Settings(audit_log=str(d / "audit.jsonl")), d / "config.toml")
    SecretStore(d / "secrets.json").set("A_SECRET", "value-value")
    (tmp_path / "state" / "mcpgate").mkdir(parents=True)
    for f in (d / "audit.jsonl", tmp_path / "state" / "mcpgate" / "oauth.json"):
        f.write_text("{}\n")
        f.chmod(0o600)
    env = {"HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path), "XDG_STATE_HOME": str(tmp_path / "state"), "PATH": "/usr/bin:/bin",
           "PYTHONPATH": str(Path(cli.__file__).parent.parent)}
    ok = subprocess.run([sys.executable, "-m", "mcpgate", "doctor", "--no-connect"], env=env, capture_output=True, text=True, timeout=120)
    assert "readable by other users" not in ok.stdout
    for f in (d / "config.toml", d / "audit.jsonl", tmp_path / "state" / "mcpgate" / "oauth.json"):
        f.chmod(0o644)
    bad = subprocess.run([sys.executable, "-m", "mcpgate", "doctor", "--no-connect"], env=env, capture_output=True, text=True, timeout=120)
    assert bad.returncode == 1
    for f in ("config.toml", "audit.jsonl", "oauth.json"):
        assert f"{f} is readable by other users" in bad.stdout, f


# ===== the one page rendered on the server: the OAuth consent page on the public listener ====================================
def test_the_consent_page_escapes_everything_an_app_can_name_and_refuses_framing(tmp_path):
    from types import SimpleNamespace

    from mcpgate.oauth import GatewayOAuth
    prov = GatewayOAuth("https://box.example.com", passphrase=PASS, state_path=tmp_path / "o.json")
    client = SimpleNamespace(client_name=EVIL)
    params = SimpleNamespace(redirect_uri="https://" + EVIL.replace("/", "") + "/cb")
    prov._pending['r"><b>'] = (client, params, None)
    resp = prov._page('r"><b>', EVIL)
    body = resp.body.decode()
    assert "<img" not in body and "<script>" not in body.split("<style>")[0] + body.split("</style>")[1] and "<b>r" not in body
    assert "&lt;img" in body and resp.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "script-src" not in resp.headers["content-security-policy"] and "default-src 'none'" in resp.headers["content-security-policy"]
