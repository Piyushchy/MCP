import re

import pytest

from mcpgate import config
from mcpgate.config import Backend, ConfigError, Settings


def test_defaults_when_file_missing(tmp_path):
    s = config.load(tmp_path / "none.toml")
    assert s.backends == {} and s.cache_ttl == 60.0 and s.max_result_chars == 20000


def test_parse_backends_and_settings():
    s = config.parse({
        "gateway": {"cache_ttl": 5, "max_result_chars": 1000, "audit_log": "/tmp/a.jsonl"},
        "backends": {
            "gh": {"command": "npx", "args": ["-y", "x"], "env": {"T": "${T}"}, "deny": ["delete_*"], "confirm": ["create_*"]},
            "remote": {"transport": "http", "url": "https://example.com/mcp", "headers": {"Authorization": "Bearer ${TOK}"}},
        },
    })
    assert s.cache_ttl == 5 and s.max_result_chars == 1000
    assert s.backends["gh"].deny == ["delete_*"] and s.backends["gh"].allow == ["*"]
    assert s.backends["remote"].transport == "http"


@pytest.mark.parametrize("data, msg", [
    ({"nope": {}}, "unknown top-level"),
    ({"gateway": {"bogus": 1}}, "unknown [gateway]"),
    ({"gateway": {"max_result_chars": 5}}, "max_result_chars"),
    ({"backends": {"Bad Name": {"command": "x"}}}, "must be lowercase"),
    ({"backends": {"a": {"transport": "carrier-pigeon", "command": "x"}}}, "transport must be"),
    ({"backends": {"a": {}}}, "needs 'command'"),
    ({"backends": {"a": {"transport": "http", "url": "ftp://x"}}}, "http(s)"),
    ({"backends": {"a": {"command": "x", "args": "notalist"}}}, "list of strings"),
    ({"backends": {"a": {"command": "x", "mystery": 1}}}, "unknown key"),
    ({"backends": {"a": {"command": "x", "enabled": "yes"}}}, "true or false"),
])
def test_invalid_configs(data, msg):
    with pytest.raises(ConfigError, match=re.escape(msg)):
        config.parse(data)


def test_expand_env():
    env = {"A": "1", "EMPTY": ""}
    assert config.expand("x-${A}-y", env) == "x-1-y"
    assert config.expand("${NOPE:-fallback}", env) == "fallback"
    assert config.expand("${EMPTY:-d}", env) == "d"
    with pytest.raises(ConfigError, match="NOPE"):
        config.expand("${NOPE}", env)


def test_save_roundtrip_and_permissions(tmp_path):
    p = tmp_path / "sub" / "config.toml"
    s = Settings(cache_ttl=10.0)
    s.backends["a"] = Backend(name="a", command="python", args=["-m", "x"], deny=["rm_*"], timeout=5)
    s.backends["drop"] = Backend(name="drop", command="python", source="custom")  # drop-ins are not saved
    config.save(s, p)
    assert (p.stat().st_mode & 0o777) == 0o600
    again = config.load(p)
    assert again.cache_ttl == 10.0 and list(again.backends) == ["a"]
    assert again.backends["a"].args == ["-m", "x"] and again.backends["a"].timeout == 5.0


def test_bad_toml_is_a_config_error(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("this is = = not toml")
    with pytest.raises(ConfigError):
        config.load(p)


def test_config_path_env(monkeypatch, tmp_path):
    monkeypatch.setenv("MCPGATE_CONFIG", str(tmp_path / "x.toml"))
    assert config.config_path() == tmp_path / "x.toml"


def test_start_timeout_parses_saves_and_is_validated(tmp_path):
    s = config.parse({"backends": {"a": {"command": "x", "start_timeout": 120}}})
    assert s.backends["a"].start_timeout == 120.0 and Backend(name="b", command="x").start_timeout == 30.0
    config.save(s, tmp_path / "c.toml")
    assert config.load(tmp_path / "c.toml").backends["a"].start_timeout == 120.0
    for bad in [{"command": "x", "start_timeout": 0}, {"command": "x", "start_timeout": "soon"}]:
        with pytest.raises(ConfigError):
            config.parse({"backends": {"a": bad}})
