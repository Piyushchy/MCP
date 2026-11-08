"""UI-02: gateway settings live in the config file; passphrases and tokens only as hashes."""
import json
import os
import re
import socket
import subprocess
import sys
import time

import httpx
import pytest

from mcpgate import authstore, cli, config
from mcpgate.authstore import AuthStore
from mcpgate.config import ConfigError, Settings
from mcpgate.oauth import GatewayOAuth


# ---- the [server] section --------------------------------------------------
def test_server_section_parses_validates_and_round_trips(tmp_path):
    s = config.parse({"server": {
        "public_url": "https://box.tail1234.ts.net:8443/", "port": 9000, "admin_port": 9001,
        "allow_hosts": ["box.tail1234.ts.net"], "oauth_enabled": True, "oauth_redirect_hosts": ["example.org"],
        "static_token_enabled": True}})
    sv = s.server
    assert sv.public_url == "https://box.tail1234.ts.net:8443" and (sv.port, sv.admin_port) == (9000, 9001)
    assert sv.oauth_enabled and sv.static_token_enabled and sv.allow_hosts == ["box.tail1234.ts.net"]
    config.save(s, tmp_path / "c.toml")
    again = config.load(tmp_path / "c.toml").server
    assert again == sv
    assert config.parse({}).server == config.Server()
    assert "server" not in config.to_data(Settings())          # defaults are not written


@pytest.mark.parametrize("server, msg", [
    ({"public_url": "http://example.com"}, "https://"),
    ({"public_url": "https://example.com/mcp"}, "without a path"),
    ({"public_url": "https://user@example.com"}, "without a path"),
    ({"port": 0}, "port number"), ({"admin_port": 70000}, "port number"), ({"port": True}, "port number"),
    ({"port": 8000, "admin_port": 8000}, "different"),
    ({"allow_hosts": ["https://x.example"]}, "bare host names"),
    ({"allow_hosts": ["x.example/path"]}, "bare host names"),
    ({"oauth_enabled": "yes"}, "true or false"),
    ({"mystery": 1}, "unknown [server]"),
])
def test_server_section_rejects_bad_values(server, msg):
    with pytest.raises(ConfigError, match=re.escape(msg)):
        config.parse({"server": server})


def test_localhost_http_is_fine_for_the_public_address():
    assert config.check_public_url("http://127.0.0.1:8791/") == "http://127.0.0.1:8791"


# ---- hashed credentials ----------------------------------------------------
def test_passphrase_is_stored_as_a_salted_scrypt_hash(tmp_path):
    st = AuthStore(tmp_path / "auth.json")
    st.set_passphrase("oauth_passphrase", "a long enough passphrase")
    text = (tmp_path / "auth.json").read_text()
    assert "a long enough passphrase" not in text and '"algo": "scrypt"' in text
    assert (tmp_path / "auth.json").stat().st_mode & 0o777 == 0o600
    assert st.verify("oauth_passphrase", "a long enough passphrase")
    assert not st.verify("oauth_passphrase", "a long enough passphrasE") and not st.verify("nope", "x")
    st.set_passphrase("admin_passphrase", "a long enough passphrase")     # same text, different salt
    recs = json.loads(text) if False else json.loads((tmp_path / "auth.json").read_text())["records"]
    assert recs["admin_passphrase"]["hash"] != recs["oauth_passphrase"]["hash"]


def test_short_passphrases_are_refused_and_nothing_is_written(tmp_path):
    st = AuthStore(tmp_path / "auth.json")
    with pytest.raises(ConfigError, match="at least 12"):
        st.set_passphrase("oauth_passphrase", "short")
    assert not (tmp_path / "auth.json").exists()


def test_static_token_is_stored_hashed_and_verifies(tmp_path):
    st = AuthStore(tmp_path / "auth.json")
    tok = authstore.new_token()
    st.set_token("static_token", tok)
    assert tok not in (tmp_path / "auth.json").read_text()
    assert st.verify("static_token", tok) and not st.verify("static_token", tok + "x")
    assert st.clear("static_token") and not st.has("static_token") and not st.clear("static_token")


def test_world_readable_auth_file_is_refused_and_later_changes_are_noticed(tmp_path):
    p = tmp_path / "auth.json"
    st = AuthStore(p)
    st.set_passphrase("oauth_passphrase", "a long enough passphrase")
    p.chmod(0o644)
    assert not st.verify("oauth_passphrase", "a long enough passphrase")   # refuses to trust it while loose
    assert "chmod 600" in st.error
    with pytest.raises(ConfigError, match="readable by other users"):
        AuthStore(p)
    p.chmod(0o600)
    assert st.verify("oauth_passphrase", "a long enough passphrase") and st.error == ""


def test_another_process_changing_the_file_is_picked_up(tmp_path):
    a, b = AuthStore(tmp_path / "auth.json"), AuthStore(tmp_path / "auth.json")
    assert not a.has("oauth_passphrase")
    b.set_passphrase("oauth_passphrase", "a long enough passphrase")
    assert a.has("oauth_passphrase") and a.verify("oauth_passphrase", "a long enough passphrase")
    b.clear("oauth_passphrase")
    assert not a.has("oauth_passphrase")


# ---- the OAuth provider using the hashed store -----------------------------
async def test_oauth_uses_the_stored_hash_and_an_env_override_wins(tmp_path):
    st = AuthStore(tmp_path / "auth.json")
    st.set_passphrase("oauth_passphrase", "stored passphrase!!")
    oa = GatewayOAuth("https://x.example", None, tmp_path / "o.json", auth=st)
    assert oa._passphrase_ok("stored passphrase!!") and not oa._passphrase_ok("wrong")
    over = GatewayOAuth("https://x.example", "env override passphrase", tmp_path / "o.json", auth=st)
    assert over._passphrase_ok("env override passphrase") and not over._passphrase_ok("stored passphrase!!")
    with pytest.raises(ValueError, match="no approval passphrase"):
        GatewayOAuth("https://x.example", None, tmp_path / "o.json", auth=AuthStore(tmp_path / "empty.json"))


async def test_static_token_from_the_store_only_when_enabled(tmp_path):
    st = AuthStore(tmp_path / "auth.json")
    st.set_passphrase("oauth_passphrase", "stored passphrase!!")
    tok = authstore.new_token()
    st.set_token("static_token", tok)
    off = GatewayOAuth("https://x.example", None, tmp_path / "o.json", auth=st, static_from_auth=False)
    on = GatewayOAuth("https://x.example", None, tmp_path / "o.json", auth=st, static_from_auth=True)
    assert await off.load_access_token(tok) is None
    assert await on.load_access_token(tok) is not None and await on.load_access_token("other") is None


# ---- the CLI ------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("MCPGATE_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    return tmp_path


def test_auth_passphrase_token_status_and_clear(home, monkeypatch, capsys):
    answers = iter(["a long enough passphrase", "a long enough passphrase"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert cli.main(["auth", "passphrase"]) == 0
    assert "a long enough passphrase" not in (home / "auth.json").read_text()
    assert cli.main(["auth", "token"]) == 0
    out = capsys.readouterr().out
    token = out.strip().splitlines()[-1]
    assert token not in (home / "auth.json").read_text() and len(token) >= 40
    assert config.load(home / "config.toml").server.static_token_enabled is True
    capsys.readouterr()
    assert cli.main(["auth", "status"]) == 0
    status = capsys.readouterr().out
    assert "approval passphrase (claude.ai)" in status and "set" in status and token not in status
    assert cli.main(["auth", "clear-token"]) == 0 and "Removed" in capsys.readouterr().out
    assert cli.main(["auth", "clear-token"]) == 0 and "not set" in capsys.readouterr().out


def test_mismatched_passphrase_entries_are_refused(home, monkeypatch, capsys):
    answers = iter(["a long enough passphrase", "something else entirely"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert cli.main(["auth", "passphrase"]) == 2
    assert not (home / "auth.json").exists()


# ---- real serve processes that take everything from the file ---------------
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_process(home, port):
    env = {**os.environ, "MCPGATE_CONFIG": str(home / "config.toml"), "XDG_CONFIG_HOME": str(home / "xdg"),
           "XDG_STATE_HOME": str(home / "state")}
    for k in ("MCPGATE_PASSPHRASE", "MCPGATE_TOKEN"):
        env.pop(k, None)
    p = subprocess.Popen([sys.executable, "-m", "mcpgate", "serve", "--http"], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p
        except OSError:
            if p.poll() is not None:
                raise AssertionError(p.stderr.read())
            time.sleep(0.1)
    p.kill()
    raise AssertionError("serve did not start")


def test_oauth_from_the_file_alone_behaves_like_the_flags(home):
    port = free_port()
    s = Settings()
    s.server = config.Server(public_url=f"http://127.0.0.1:{port}", port=port, oauth_enabled=True)
    config.save(s, home / "config.toml")
    AuthStore(home / "auth.json").set_passphrase("oauth_passphrase", "a long enough passphrase")
    p = serve_process(home, port)
    try:
        r = httpx.post(f"http://127.0.0.1:{port}/mcp", json={})
        assert r.status_code == 401 and "resource_metadata" in r.headers["www-authenticate"]
        meta = httpx.get(f"http://127.0.0.1:{port}/.well-known/oauth-authorization-server").json()
        assert meta["registration_endpoint"].endswith("/register")
    finally:
        p.terminate()
        p.wait(10)
    assert "a long enough passphrase" not in (home / "auth.json").read_text()


def test_hashed_static_token_protects_a_plain_http_gateway(home):
    port = free_port()
    s = Settings()
    s.server = config.Server(port=port, static_token_enabled=True)
    config.save(s, home / "config.toml")
    st = AuthStore(home / "auth.json")
    tok = authstore.new_token()
    st.set_token("static_token", tok)
    p = serve_process(home, port)
    hdr = {"Accept": "application/json, text/event-stream"}
    try:
        url = f"http://127.0.0.1:{port}/mcp"
        assert httpx.post(url, json={}, headers=hdr).status_code == 401
        assert httpx.post(url, json={}, headers={**hdr, "Authorization": "Bearer nope"}).status_code == 401
        assert httpx.post(url, json={}, headers={**hdr, "Authorization": f"Bearer {tok}"}).status_code != 401
    finally:
        p.terminate()
        p.wait(10)


def test_serve_without_a_passphrase_says_how_to_set_one(home, capsys, monkeypatch):
    monkeypatch.delenv("MCPGATE_PASSPHRASE", raising=False)
    s = Settings()
    s.server = config.Server(public_url="https://x.example", oauth_enabled=True)
    config.save(s, home / "config.toml")
    assert cli.main(["serve", "--http"]) == 2
    assert "mcpgate auth passphrase" in capsys.readouterr().err


def test_serve_off_loopback_without_any_credential_is_refused(home, capsys, monkeypatch):
    monkeypatch.delenv("MCPGATE_TOKEN", raising=False)
    assert cli.main(["serve", "--http", "--host", "0.0.0.0"]) == 2
    assert "auth token" in capsys.readouterr().err
