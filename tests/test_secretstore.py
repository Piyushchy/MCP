import json
import os
import stat
import sys
from pathlib import Path

import pytest

from mcpgate import cli
from mcpgate.config import Backend, ConfigError, Settings, expand
from mcpgate.hub import Hub, GatewayError
from mcpgate.secretstore import SecretStore

DEMO = str(Path(__file__).parent / "fixtures" / "demo_server.py")
CANARY = "canary-s3cr3t-7f3a91c2"


def demo(name="demo", **kw):
    return Backend(name=name, transport="stdio", command=sys.executable, args=[DEMO], **kw)


def test_store_basics_mode_and_names_only(tmp_path):
    p = tmp_path / "secrets.json"
    s = SecretStore(p)
    s.set("GITHUB_TOKEN", CANARY)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert s.get("GITHUB_TOKEN") == CANARY
    listing = s.names()
    assert listing[0]["name"] == "GITHUB_TOKEN" and CANARY not in json.dumps(listing)
    assert s.delete("GITHUB_TOKEN") and not s.has("GITHUB_TOKEN") and not s.delete("GITHUB_TOKEN")


@pytest.mark.parametrize("name", ["", "1ABC", "a-b", "a b", "x" * 65])
def test_bad_names_rejected(tmp_path, name):
    with pytest.raises(ConfigError):
        SecretStore(tmp_path / "s.json").set(name, "value")


@pytest.mark.parametrize("value", ["", "a\x00b", "x" * 9000])
def test_bad_values_rejected(tmp_path, value):
    with pytest.raises(ConfigError):
        SecretStore(tmp_path / "s.json").set("TOK", value)


def test_refuses_world_readable_file(tmp_path):
    p = tmp_path / "s.json"
    SecretStore(p).set("A", "valuevalue")
    p.chmod(0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        SecretStore(p)


def test_picks_up_outside_change_and_bad_perms_at_runtime(tmp_path):
    p = tmp_path / "s.json"
    a, b = SecretStore(p), SecretStore(p)
    a.set("A", "first-value")
    assert b.get("A") == "first-value"
    p.chmod(0o644)
    assert b.get("A") is None and "chmod 600" in b.error   # unusable, not silently used


def test_expand_env_wins_then_store_then_default():
    lookup = {"X": "from-store"}.get
    assert expand("${X}", environ={"X": "from-env"}, lookup=lookup) == "from-env"
    assert expand("${X}", environ={}, lookup=lookup) == "from-store"
    assert expand("${Y:-d}", environ={}, lookup=lookup) == "d"
    with pytest.raises(ConfigError):
        expand("${Y}", environ={}, lookup=lookup)


def test_scrub_blanks_values_but_not_short_ones(tmp_path):
    s = SecretStore(tmp_path / "s.json")
    s.set("A", CANARY)
    s.set("B", "abc")
    assert s.scrub(f"bad {CANARY} here abc") == "bad *** here abc"


async def test_backend_receives_secret_from_store(tmp_path):
    store = SecretStore(tmp_path / "s.json")
    store.set("DEMO_KEY", CANARY)
    hub = Hub(Settings(backends={"demo": demo(env={"DEMO_KEY": "${DEMO_KEY}"})}), secrets=store)
    try:
        out = await hub.call("demo.listenv", {"prefix": "DEMO_"})
        assert "DEMO_KEY" in str(out)
    finally:
        await hub.stop()


async def test_missing_secret_error_names_it_without_values(tmp_path):
    hub = Hub(Settings(backends={"demo": demo(env={"K": "${NOPE_NOT_SET}"})}), secrets=SecretStore(tmp_path / "s.json"))
    try:
        with pytest.raises(Exception) as e:
            await hub.call("demo.echo", {"text": "x"})
        assert "NOPE_NOT_SET" in str(e.value)
    finally:
        await hub.stop()


async def test_canary_never_leaks_in_errors_or_audit(tmp_path):
    store = SecretStore(tmp_path / "s.json")
    store.set("DEMO_KEY", CANARY)
    audit = tmp_path / "audit.jsonl"
    hub = Hub(Settings(audit_log=str(audit), backends={"demo": demo(env={"DEMO_KEY": "${DEMO_KEY}"})}), secrets=store)
    try:
        with pytest.raises(GatewayError) as e:
            await hub.call("demo.shout", {"text": CANARY})   # the tool echoes the secret in its error
        assert CANARY not in str(e.value)
    finally:
        await hub.stop()
    assert CANARY not in audit.read_text()


async def test_changed_secret_restarts_only_users(tmp_path):
    store = SecretStore(tmp_path / "s.json")
    store.set("K1", "value-one-1")
    hub = Hub(Settings(backends={
        "a": demo("a", env={"K": "${K1}"}),
        "b": demo("b"),
    }), secrets=store)
    try:
        await hub.call("a.echo", {"text": "x"})
        await hub.call("b.echo", {"text": "x"})
        before = {n: b._task for n, b in hub.backends.items()}   # keep references so ids cannot be reused
        store.set("K1", "value-two-2")
        assert await hub.apply_secret_changes() == ["a"]
        await hub.call("a.echo", {"text": "x"})
        assert hub.backends["a"]._task is not before["a"] and hub.backends["b"]._task is before["b"]
        assert await hub.apply_secret_changes() == []
    finally:
        await hub.stop()


def test_cli_secret_set_list_remove_and_canary(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MCPGATE_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setattr("getpass.getpass", lambda *_: CANARY)
    assert cli.main(["secret", "set", "GITHUB_TOKEN"]) == 0
    assert cli.main(["secret", "list"]) == 0
    assert cli.main(["secret", "set", "bad-name"]) != 0
    assert cli.main(["secret", "remove", "GITHUB_TOKEN"]) == 0
    out = capsys.readouterr()
    assert CANARY not in out.out + out.err and "GITHUB_TOKEN" in out.out
    assert not SecretStore(tmp_path / "secrets.json").has("GITHUB_TOKEN")


def test_doctor_reports_missing_and_stored(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MCPGATE_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("DOC_A", raising=False)
    monkeypatch.delenv("DOC_B", raising=False)
    SecretStore(tmp_path / "secrets.json").set("DOC_B", CANARY)
    cli.main(["add", "docs", "--env", "A=${DOC_A}", "--env", "B=${DOC_B}", "--", sys.executable, DEMO])
    rc = cli.main(["doctor", "--no-connect"])
    out = capsys.readouterr().out
    assert rc == 1 and "DOC_A is NOT set" in out and "DOC_B is set (secrets store)" in out and CANARY not in out
