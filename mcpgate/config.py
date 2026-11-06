"""Gateway configuration: a TOML file listing backends and a few settings.

Secrets are never stored in the file. Values may reference environment
variables as ``${NAME}`` or ``${NAME:-default}``; they are expanded only when a
backend starts, so loading a config never fails on a missing secret.
"""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import tomli_w

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
TRANSPORTS = ("stdio", "http", "sse")


class ConfigError(ValueError):
    """The config file (or a value in it) is not usable."""


def config_path() -> Path:
    env = os.environ.get("MCPGATE_CONFIG")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "mcpgate" / "config.toml"


def expand(value: str, environ=None) -> str:
    """Replace ${VAR} / ${VAR:-default}. A missing variable without a default is an error."""
    environ = os.environ if environ is None else environ

    def sub(m):
        name, default = m.group(1), m.group(2)
        if name in environ and environ[name] != "":
            return environ[name]
        if default is not None:
            return default
        raise ConfigError(f"environment variable {name} is not set")

    return ENV_RE.sub(sub, value)


@dataclass
class Backend:
    name: str
    transport: str = "stdio"
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str = ""
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    allow: list[str] = field(default_factory=lambda: ["*"])
    deny: list[str] = field(default_factory=list)
    confirm: list[str] = field(default_factory=list)
    enabled: bool = True
    timeout: float = 60.0
    description: str = ""
    source: str = "config"  # "config" or "custom" (a drop-in file)

    def validate(self) -> None:
        if not NAME_RE.match(self.name):
            raise ConfigError(
                f"backend name {self.name!r} must be lowercase letters, digits, '-' or '_' (max 32)")
        if self.transport not in TRANSPORTS:
            raise ConfigError(f"[{self.name}] transport must be one of {', '.join(TRANSPORTS)}")
        if self.transport == "stdio" and not self.command:
            raise ConfigError(f"[{self.name}] a stdio backend needs 'command'")
        if self.transport != "stdio":
            if not self.url.startswith(("http://", "https://", "${")):
                raise ConfigError(f"[{self.name}] a {self.transport} backend needs an http(s) 'url'")
        if self.timeout <= 0:
            raise ConfigError(f"[{self.name}] timeout must be positive")

    def to_dict(self) -> dict:
        d: dict = {"transport": self.transport}
        if self.transport == "stdio":
            d["command"] = self.command
            if self.args:
                d["args"] = list(self.args)
            if self.env:
                d["env"] = dict(self.env)
            if self.cwd:
                d["cwd"] = self.cwd
        else:
            d["url"] = self.url
            if self.headers:
                d["headers"] = dict(self.headers)
        if self.allow != ["*"]:
            d["allow"] = list(self.allow)
        if self.deny:
            d["deny"] = list(self.deny)
        if self.confirm:
            d["confirm"] = list(self.confirm)
        if not self.enabled:
            d["enabled"] = False
        if self.timeout != 60.0:
            d["timeout"] = self.timeout
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class Settings:
    cache_ttl: float = 60.0          # seconds a read-only result is reused (0 turns the cache off)
    tools_ttl: float = 300.0         # seconds a backend's tool list is reused
    max_result_chars: int = 20000    # longer text results are cut and can be paged with read_result
    audit_log: str = ""              # JSONL file of every call ("" turns it off)
    custom_dir: str = ""             # folder of drop-in custom MCP servers ("" = default folder)
    backends: dict[str, Backend] = field(default_factory=dict)


_GATEWAY_KEYS = {"cache_ttl", "tools_ttl", "max_result_chars", "audit_log", "custom_dir"}
_BACKEND_KEYS = {"transport", "command", "args", "env", "cwd", "url", "headers", "allow", "deny",
                 "confirm", "enabled", "timeout", "description"}


def _strlist(name: str, key: str, v) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"[{name}] '{key}' must be a list of strings")
    return list(v)


def _strmap(name: str, key: str, v) -> dict[str, str]:
    if not isinstance(v, dict) or not all(isinstance(k, str) and isinstance(x, str) for k, x in v.items()):
        raise ConfigError(f"[{name}] '{key}' must be a table of strings")
    return dict(v)


def parse(data: dict) -> Settings:
    unknown = set(data) - {"gateway", "backends"}
    if unknown:
        raise ConfigError(f"unknown top-level section(s): {', '.join(sorted(unknown))}")
    s = Settings()
    g = data.get("gateway", {})
    bad = set(g) - _GATEWAY_KEYS
    if bad:
        raise ConfigError(f"unknown [gateway] key(s): {', '.join(sorted(bad))}")
    for key in ("cache_ttl", "tools_ttl"):
        if key in g:
            if not isinstance(g[key], (int, float)) or g[key] < 0:
                raise ConfigError(f"[gateway] {key} must be a number >= 0")
            setattr(s, key, float(g[key]))
    if "max_result_chars" in g:
        if not isinstance(g["max_result_chars"], int) or g["max_result_chars"] < 200:
            raise ConfigError("[gateway] max_result_chars must be an integer >= 200")
        s.max_result_chars = g["max_result_chars"]
    for key in ("audit_log", "custom_dir"):
        if key in g:
            if not isinstance(g[key], str):
                raise ConfigError(f"[gateway] {key} must be a string")
            setattr(s, key, g[key])

    for name, raw in data.get("backends", {}).items():
        if not isinstance(raw, dict):
            raise ConfigError(f"[backends.{name}] must be a table")
        bad = set(raw) - _BACKEND_KEYS
        if bad:
            raise ConfigError(f"[backends.{name}] unknown key(s): {', '.join(sorted(bad))}")
        b = Backend(name=name)
        for key, value in raw.items():
            if key in ("args", "allow", "deny", "confirm"):
                setattr(b, key, _strlist(name, key, value))
            elif key in ("env", "headers"):
                setattr(b, key, _strmap(name, key, value))
            elif key == "enabled":
                if not isinstance(value, bool):
                    raise ConfigError(f"[{name}] 'enabled' must be true or false")
                b.enabled = value
            elif key == "timeout":
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    raise ConfigError(f"[{name}] 'timeout' must be a number")
                b.timeout = float(value)
            else:
                if not isinstance(value, str):
                    raise ConfigError(f"[{name}] '{key}' must be a string")
                setattr(b, key, value)
        b.validate()
        s.backends[name] = b
    return s


def load(path: Path | str | None = None) -> Settings:
    p = Path(path).expanduser() if path else config_path()
    if not p.exists():
        return Settings()
    try:
        data = tomllib.loads(p.read_text())
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{p}: {e}") from None
    return parse(data)


def to_data(s: Settings) -> dict:
    g = {}
    defaults = Settings()
    for key in sorted(_GATEWAY_KEYS):
        if getattr(s, key) != getattr(defaults, key):
            g[key] = getattr(s, key)
    out: dict = {}
    if g:
        out["gateway"] = g
    out["backends"] = {n: b.to_dict() for n, b in sorted(s.backends.items()) if b.source == "config"}
    return out


def save(s: Settings, path: Path | str | None = None) -> Path:
    p = Path(path).expanduser() if path else config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(tomli_w.dumps(to_data(s)))
    os.chmod(tmp, 0o600)  # the file may name credentials-bearing commands
    tmp.replace(p)
    return p
