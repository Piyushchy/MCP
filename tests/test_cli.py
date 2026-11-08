import sys

import pytest

from mcpgate import cli, config
from tests.conftest import DEMO


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    p = tmp_path / "config.toml"
    monkeypatch.setenv("MCPGATE_CONFIG", str(p))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))  # keeps the real custom folder out of tests
    return p


def run(*argv):
    return cli.main(list(argv))


def test_init_creates_a_private_starter_that_loads(cfg, capsys):
    assert run("init") == 0
    assert (cfg.stat().st_mode & 0o777) == 0o600
    assert config.load(cfg).backends == {}
    assert run("init") == 0 and "already exists" in capsys.readouterr().out


def test_add_stdio_with_policy_then_list_and_remove(cfg, capsys):
    assert run("add", "demo", "--deny", "die", "--confirm", "create_*", "--env", "DEMO_SECRET=${TOK}",
               "--", sys.executable, DEMO) == 0
    b = config.load(cfg).backends["demo"]
    assert b.command == sys.executable and b.args == [DEMO] and b.deny == ["die"] and b.env == {"DEMO_SECRET": "${TOK}"}
    capsys.readouterr()
    assert run("list") == 0
    out = capsys.readouterr().out
    assert out.startswith("demo") and "stdio" in out and "deny=1 confirm=1" in out
    assert run("remove", "demo") == 0 and config.load(cfg).backends == {}


def test_add_remote_and_duplicate_and_bad_input(cfg, capsys):
    assert run("add", "docs", "--url", "https://example.com/mcp", "--sse", "--header", "Authorization=Bearer ${T}") == 0
    assert config.load(cfg).backends["docs"].transport == "sse"
    assert run("add", "docs", "--url", "https://x.test/mcp") == 2 and "already exists" in capsys.readouterr().err
    assert run("add", "nocmd") == 2
    assert run("add", "both", "--url", "https://x.test", "--", "cmd") == 2
    assert run("add", "Bad Name", "--", "cmd") == 2
    assert run("remove", "ghost") == 2


def test_literal_secrets_are_refused(cfg, capsys):
    assert run("add", "x", "--env", "API_KEY=sk-live-123", "--", "cmd") == 2
    err = capsys.readouterr().err
    assert "looks like a secret" in err and "sk-live-123" not in err  # the value is never echoed back
    assert "x" not in config.load(cfg).backends  # and nothing was written
    assert run("add", "y", "--header", "Authorization=Bearer abc", "--url", "https://x.test") == 2
    assert run("add", "ok", "--env", "API_KEY=${API_KEY}", "--", "cmd") == 0


def test_enable_disable(cfg):
    run("add", "demo", "--", sys.executable, DEMO)
    run("disable", "demo")
    assert config.load(cfg).backends["demo"].enabled is False
    run("enable", "demo")
    assert config.load(cfg).backends["demo"].enabled is True


def test_new_creates_a_drop_in_that_list_shows(cfg, capsys):
    assert run("new", "scratch") == 0
    assert run("new", "scratch") == 2
    capsys.readouterr()
    run("list")
    out = capsys.readouterr().out
    assert "scratch" in out and "custom" in out


def test_tools_command_connects(cfg, capsys):
    run("add", "demo", "--deny", "die", "--", sys.executable, DEMO)
    capsys.readouterr()
    assert run("tools", "demo") == 0
    cap = capsys.readouterr()
    assert "demo.echo" in cap.out and "demo.die" not in cap.out and "tools" in cap.err
    assert run("tools", "ghost") == 1


def test_doctor_reports_problems_and_passes_when_fine(cfg, capsys, monkeypatch):
    run("add", "ghost", "--env", "T=${MISSING_FOR_SURE}", "--", "/no/such/cmd")
    monkeypatch.delenv("MISSING_FOR_SURE", raising=False)
    capsys.readouterr()
    assert run("doctor", "--no-connect") == 1
    out = capsys.readouterr().out
    assert "MISSING_FOR_SURE is NOT set" in out and "not found" in out

    run("remove", "ghost")
    run("add", "demo", "--", sys.executable, DEMO)
    capsys.readouterr()
    assert run("doctor") == 0
    assert "connected" in capsys.readouterr().out


def test_doctor_flags_a_world_readable_config(cfg, capsys):
    run("add", "demo", "--", sys.executable, DEMO)
    cfg.chmod(0o644)
    assert run("doctor", "--no-connect") == 1
    assert "readable by other users" in capsys.readouterr().out


def test_broken_config_is_a_clean_error(cfg, capsys):
    cfg.write_text("[backends.x]\nbogus = 1\ncommand='c'\n")
    assert run("list") == 2 and "unknown key" in capsys.readouterr().err


def test_token_is_long_and_random(capsys):
    run("token")
    a = capsys.readouterr().out.strip()
    run("token")
    b = capsys.readouterr().out.strip()
    assert len(a) >= 40 and a != b


def test_serve_over_http_needs_a_token_off_loopback(cfg, capsys, monkeypatch):
    monkeypatch.delenv("MCPGATE_TOKEN", raising=False)
    assert run("serve", "--http", "--host", "0.0.0.0") == 2
    assert "needs a token" in capsys.readouterr().err


def test_add_accepts_start_timeout(cfg):
    assert run("add", "slow", "--start-timeout", "90", "--", "npx", "-y", "something") == 0
    assert config.load(cfg).backends["slow"].start_timeout == 90.0
