import json
import re

import pytest
from starlette.testclient import TestClient

from mcpgate.admin import app as admin
from mcpgate.admin.session import ABSOLUTE, COOKIE, IDLE, SETUP_TTL, STEPUP, AdminAuth
from mcpgate.authstore import AuthStore

PORT = 8767
HOST = f"127.0.0.1:{PORT}"
H = {"host": HOST, "origin": f"http://{HOST}"}
PASS = "correct horse battery"


class Clock:
    now = 1_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def env(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr("time.time", clock)   # AuthStore expiry uses time.time too
    store = AuthStore(tmp_path / "auth.json")
    events = []
    auth = AdminAuth(store, clock=clock, audit=lambda **f: events.append(f))
    c = TestClient(admin.make_app(PORT, auth=auth), base_url=f"http://{HOST}")
    return c, auth, store, clock, events


def post_json(c, path, data=None, csrf=None):
    h = {**H, "content-type": "application/json", **({"x-csrf-token": csrf} if csrf else {})}
    return c.post(path, headers=h, content=json.dumps(data if data is not None else {}))


def setup(env):
    c, auth, *_ = env
    code = auth.issue_setup_code()
    r = post_json(c, "/api/setup", {"code": code, "passphrase": PASS})
    assert r.status_code == 200, r.text
    return r.json()["csrf"]


def test_first_run_is_setup_and_code_is_single_use(env):
    c, auth, store, *_ = env
    assert c.get("/api/session", headers={"host": HOST}).json() == {"state": "setup"}
    assert post_json(c, "/api/login", {"passphrase": PASS}).status_code == 409   # no login before setup
    code = auth.issue_setup_code()
    assert re.fullmatch(r"[A-Z2-9]{5}(-[A-Z2-9]{5}){3}", code)
    assert post_json(c, "/api/setup", {"code": "WRONG-CODE", "passphrase": PASS}).status_code == 403
    assert post_json(c, "/api/setup", {"code": code, "passphrase": "short"}).status_code == 400
    r = post_json(c, "/api/setup", {"code": code.lower().replace("-", " "), "passphrase": PASS})   # forgiving about case/format
    assert r.status_code == 200 and r.json()["state"] == "ready"
    assert not store.has("admin_setup") and store.has("admin_passphrase")
    assert PASS not in (store.path.read_text())
    assert post_json(c, "/api/setup", {"code": code, "passphrase": "another passphrase"}).status_code == 409


def test_setup_code_expires(env):
    c, auth, _, clock, _ = env
    code = auth.issue_setup_code()
    clock.now += SETUP_TTL + 1
    assert post_json(c, "/api/setup", {"code": code, "passphrase": PASS}).status_code == 403


def test_setup_code_guessing_is_locked_out(env):
    c, auth, *_ = env
    code = auth.issue_setup_code()
    codes = [post_json(c, "/api/setup", {"code": f"BAD{i}", "passphrase": PASS}).status_code for i in range(5)]
    assert codes[:3] == [403] * 3 and 429 in codes
    assert post_json(c, "/api/setup", {"code": code, "passphrase": PASS}).status_code == 429   # even the right one waits


def test_login_cookie_flags_and_fresh_session_each_time(env):
    c, *_ = env
    setup(env)
    r1 = post_json(c, "/api/login", {"passphrase": PASS})
    cookie = r1.headers["set-cookie"]
    assert "httponly" in cookie.lower() and "samesite=strict" in cookie.lower() and "path=/" in cookie.lower()
    assert "max-age" not in cookie.lower() and "expires" not in cookie.lower()   # a session cookie
    sid1 = r1.cookies[COOKIE]
    c.cookies.clear()
    sid2 = post_json(c, "/api/login", {"passphrase": PASS}).cookies[COOKIE]
    assert sid1 != sid2


def test_wrong_passphrase_and_lockout(env):
    c, auth, _, clock, events = env
    setup(env)
    c.cookies.clear()
    statuses = [post_json(c, "/api/login", {"passphrase": "nope-nope-nope"}).status_code for _ in range(6)]
    assert statuses[:3] == [401] * 3 and statuses[-1] == 429
    r = post_json(c, "/api/login", {"passphrase": PASS})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    clock.now += 1000
    assert post_json(c, "/api/login", {"passphrase": PASS}).status_code == 200
    assert any(e["event"] == "admin_login_failed" for e in events)
    assert PASS not in json.dumps(events) and "nope-nope" not in json.dumps(events)


def test_protected_routes_need_session_then_csrf(env):
    c, *_ = env
    for path in ["/api/logout", "/api/stepup", "/api/passphrase"]:
        assert post_json(c, path).status_code == 401                      # no session
    csrf = setup(env)
    for path in ["/api/stepup", "/api/passphrase"]:
        assert post_json(c, path, {}).status_code == 403                  # session but no CSRF token
        assert post_json(c, path, {}, csrf="wrong").status_code == 403
    assert post_json(c, "/api/stepup", {"passphrase": PASS}, csrf=csrf).status_code == 200


def test_cookie_alone_from_another_origin_is_not_enough(env):
    c, *_ = env
    csrf = setup(env)
    h = {"host": HOST, "origin": "https://evil.example", "content-type": "application/json", "x-csrf-token": csrf}
    assert c.post("/api/stepup", headers=h, content="{}").status_code == 403


def test_json_only_and_size_limit(env):
    c, *_ = env
    h = {**H, "content-type": "text/plain"}
    assert c.post("/api/login", headers=h, content="x").status_code == 415
    assert post_json(c, "/api/login", {"passphrase": "x" * 40000}).status_code == 413


def test_idle_and_absolute_expiry(env):
    c, auth, _, clock, _ = env
    setup(env)
    assert c.get("/api/session", headers={"host": HOST}).json()["state"] == "ready"
    clock.now += IDLE - 5
    assert c.get("/api/session", headers={"host": HOST}).json()["state"] == "ready"   # activity keeps it alive
    clock.now += IDLE + 5
    assert c.get("/api/session", headers={"host": HOST}).json()["state"] == "login"
    post_json(c, "/api/login", {"passphrase": PASS})
    for _ in range(20):                                                            # busy, but 8 hours is the limit
        clock.now += ABSOLUTE / 16
        c.get("/api/session", headers={"host": HOST})
    assert c.get("/api/session", headers={"host": HOST}).json()["state"] == "login"


def test_logout_kills_the_session_server_side(env):
    c, *_ = env
    csrf = setup(env)
    stolen = c.cookies.get(COOKIE)
    assert post_json(c, "/api/logout", {}, csrf=csrf).status_code == 200
    c.cookies.set(COOKIE, stolen)
    assert c.get("/api/session", headers={"host": HOST}).json()["state"] == "login"


def test_stepup_window(env):
    c, auth, _, clock, _ = env
    csrf = setup(env)
    sess = next(iter(auth.sessions.values()))
    assert not auth.stepup_ok(sess)
    assert post_json(c, "/api/stepup", {"passphrase": "wrong-wrong-wrong"}, csrf=csrf).status_code == 401
    assert post_json(c, "/api/stepup", {"passphrase": PASS}, csrf=csrf).json()["stepup"] is True
    clock.now += STEPUP - 1
    assert auth.stepup_ok(sess)
    clock.now += 2
    assert not auth.stepup_ok(sess)


def test_change_passphrase_signs_everyone_else_out(env):
    c, auth, store, *_ = env
    csrf = setup(env)
    other = TestClient(admin.make_app(PORT, auth=auth), base_url=f"http://{HOST}")
    post_json(other, "/api/login", {"passphrase": PASS})
    assert other.get("/api/session", headers={"host": HOST}).json()["state"] == "ready"
    assert post_json(c, "/api/passphrase", {"current": "wrong-wrong-wrong", "new": "brand new passphrase"}, csrf=csrf).status_code == 401
    assert post_json(c, "/api/passphrase", {"current": PASS, "new": "short"}, csrf=csrf).status_code == 400
    r = post_json(c, "/api/passphrase", {"current": PASS, "new": "brand new passphrase"}, csrf=csrf)
    assert r.status_code == 200 and c.get("/api/session", headers={"host": HOST}).json()["state"] == "ready"
    assert other.get("/api/session", headers={"host": HOST}).json()["state"] == "login"
    assert store.verify("admin_passphrase", "brand new passphrase") and not store.verify("admin_passphrase", PASS)


def test_clearing_the_passphrase_from_the_shell_signs_everyone_out(env):
    c, auth, store, *_ = env
    setup(env)
    store.clear("admin_passphrase")
    assert c.get("/api/session", headers={"host": HOST}).json() == {"state": "setup"}


def test_route_table_rules():
    """Every state-changing route needs a session and CSRF, except the two that create the session."""
    auth = AdminAuth.__new__(AdminAuth)   # routes() only closes over it
    from mcpgate.admin.api import routes
    for s in admin.ROUTES + routes(auth):
        if s.state_changing and s.path not in admin.PRE_AUTH:
            assert s.session and s.csrf, s.path
    assert admin.PRE_AUTH == {"/api/setup", "/api/login"}


def test_auth_file_has_no_plaintext(env):
    setup(env)
    text = env[2].path.read_text()
    assert PASS not in text and "scrypt" in text


def test_session_responses_never_contain_the_passphrase(env):
    c, *_ = env
    csrf = setup(env)
    for r in [c.get("/api/session", headers={"host": HOST}), post_json(c, "/api/stepup", {"passphrase": PASS}, csrf=csrf),
              post_json(c, "/api/login", {"passphrase": "bad-bad-bad-bad"})]:
        assert PASS not in r.text and "bad-bad" not in r.text


def test_cli_ui_code_and_clear_admin(tmp_path, monkeypatch, capsys):
    from mcpgate import cli
    monkeypatch.setenv("MCPGATE_CONFIG", str(tmp_path / "config.toml"))
    assert cli.main(["ui-code"]) == 0
    code = re.search(r"[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}", capsys.readouterr().out).group(0)
    store = AuthStore(tmp_path / "auth.json")
    a = AdminAuth(store)
    cookie, _ = a.setup(code, PASS)
    assert cookie and cli.main(["ui-code"]) != 0               # already set up: no new code
    assert cli.main(["auth", "clear-admin"]) == 0
    assert AdminAuth(AuthStore(tmp_path / "auth.json")).state() == "setup"
    assert cli.main(["ui-code"]) == 0
