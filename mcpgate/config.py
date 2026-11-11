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


def expand(value: str, environ=None, lookup=None) -> str:
    """Replace ${VAR} / ${VAR:-default}. The real environment is consulted first, then ``lookup(name)``
    (the secrets store). A missing variable without a default is an error."""
    environ = os.environ if environ is None else environ

    def sub(m):
        name, default = m.group(1), m.group(2)
        if name in environ and environ[name] != "":
            return environ[name]
        found = lookup(name) if lookup else None
        if found:
            return found
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
    start_timeout: float = 30.0      # seconds to wait for the server to start (first runs of npx/uvx download packages)
    description: str = ""
    source: str = "config"  # "config" or "custom" (a drop-in file)
    preset: str = ""        # id of the shipped preset this backend was made from ("" = hand-written or custom command)

    def connection_key(self) -> tuple:
        """Everything that decides how the server is started or reached. If this is unchanged, a reload
        keeps the running connection; policy, description and call timeout can change without a restart."""
        return (self.transport, self.command, tuple(self.args), tuple(sorted(self.env.items())), self.cwd,
                self.url, tuple(sorted(self.headers.items())), self.enabled, self.start_timeout)

    def secret_refs(self) -> set[str]:
        """Names this backend references as ${NAME} anywhere in its settings."""
        refs: set[str] = set()
        for text in [self.command, self.cwd, self.url, *self.args, *self.env.values(), *self.headers.values()]:
            refs |= {m.group(1) for m in ENV_RE.finditer(text)}
        return refs

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
        if self.timeout <= 0 or self.start_timeout <= 0:
            raise ConfigError(f"[{self.name}] timeout and start_timeout must be positive")

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
        if self.start_timeout != 30.0:
            d["start_timeout"] = self.start_timeout
        if self.description:
            d["description"] = self.description
        if self.preset:
            d["preset"] = self.preset
        return d


def private_dir(p: Path) -> None:
    """Create the folder that holds config, secrets, passphrase hashes or state, readable by this user only.
    Only a folder literally named "mcpgate" is tightened, so a path pointed at a shared folder is never changed."""
    p.mkdir(parents=True, exist_ok=True)
    if p.name == "mcpgate":
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass


def check_backend_url(url: str) -> str:
    """The address of a remote MCP server: https (http only for this computer), no embedded credentials,
    no other schemes. Addresses that still contain a ${NAME} are checked when they are expanded."""
    from urllib.parse import urlparse
    url = url.strip()
    if "${" in url:
        return url
    if len(url) > 2000 or any(c in url for c in "\r\n\x00 "):
        raise ConfigError("that address is not valid")
    u = urlparse(url)
    local = u.hostname in ("localhost", "127.0.0.1", "::1")
    if u.scheme != "https" and not (u.scheme == "http" and local):
        raise ConfigError("the address must start with https:// (http:// is only allowed for localhost)")
    if not u.hostname:
        raise ConfigError("the address needs a host name")
    if u.username or u.password:
        raise ConfigError("do not put a user name or password in the address; use a header and mark it secret")
    return url


HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


def check_public_url(url: str) -> str:
    """The address clients use to reach the gateway: https (http only for localhost), no path."""
    from urllib.parse import urlparse
    u = urlparse(url.strip())
    if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1")):
        raise ConfigError("the public address must start with https:// (for example your Funnel URL)")
    if not u.hostname or u.path not in ("", "/") or u.query or u.fragment or u.username:
        raise ConfigError("the public address must be just the site (https://host or https://host:port), without a path")
    return url.strip().rstrip("/")


@dataclass
class Server:
    """How the gateway is reached. Passphrases and tokens are NOT here: they live hashed in auth.json."""
    public_url: str = ""
    port: int = 8766
    admin_port: int = 8767
    allow_hosts: list[str] = field(default_factory=list)
    oauth_enabled: bool = False
    oauth_redirect_hosts: list[str] = field(default_factory=list)
    static_token_enabled: bool = False
    allow_custom_commands: bool = True    # the admin UI may add programs that run on this computer (each one asks for the passphrase again)
    wizard_done: bool = False             # the first-run setup guide was finished or skipped


@dataclass
class Settings:
    cache_ttl: float = 60.0          # seconds a read-only result is reused (0 turns the cache off)
    tools_ttl: float = 300.0         # seconds a backend's tool list is reused
    max_result_chars: int = 20000    # longer text results are cut and can be paged with read_result
    audit_log: str = ""              # JSONL file of every call ("" turns it off)
    audit_max_mb: int = 10           # the log is rotated when it reaches this size
    audit_keep: int = 5              # how many rotated files are kept (audit.jsonl.1 ... .N)
    custom_dir: str = ""             # folder of drop-in custom MCP servers ("" = default folder)
    backends: dict[str, Backend] = field(default_factory=dict)
    server: Server = field(default_factory=Server)


_GATEWAY_KEYS = {"cache_ttl", "tools_ttl", "max_result_chars", "audit_log", "audit_max_mb", "audit_keep", "custom_dir"}
_SERVER_KEYS = {"public_url", "port", "admin_port", "allow_hosts", "oauth_enabled", "oauth_redirect_hosts", "static_token_enabled",
                "allow_custom_commands", "wizard_done"}
_BACKEND_KEYS = {"transport", "command", "args", "env", "cwd", "url", "headers", "allow", "deny",
                 "confirm", "enabled", "timeout", "start_timeout", "description", "preset"}


def _strlist(name: str, key: str, v) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"[{name}] '{key}' must be a list of strings")
    return list(v)


def _strmap(name: str, key: str, v) -> dict[str, str]:
    if not isinstance(v, dict) or not all(isinstance(k, str) and isinstance(x, str) for k, x in v.items()):
        raise ConfigError(f"[{name}] '{key}' must be a table of strings")
    return dict(v)


def parse(data: dict) -> Settings:
    unknown = set(data) - {"gateway", "backends", "server"}
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
    for key, lo, hi in (("audit_max_mb", 1, 1000), ("audit_keep", 1, 50)):
        if key in g:
            if isinstance(g[key], bool) or not isinstance(g[key], int) or not lo <= g[key] <= hi:
                raise ConfigError(f"[gateway] {key} must be a whole number from {lo} to {hi}")
            setattr(s, key, g[key])
    for key in ("audit_log", "custom_dir"):
        if key in g:
            if not isinstance(g[key], str):
                raise ConfigError(f"[gateway] {key} must be a string")
            setattr(s, key, g[key])

    sv = data.get("server", {})
    if not isinstance(sv, dict):
        raise ConfigError("[server] must be a table")
    bad = set(sv) - _SERVER_KEYS
    if bad:
        raise ConfigError(f"unknown [server] key(s): {', '.join(sorted(bad))}")
    if "public_url" in sv:
        if not isinstance(sv["public_url"], str):
            raise ConfigError("[server] public_url must be a string")
        s.server.public_url = check_public_url(sv["public_url"]) if sv["public_url"] else ""
    for key in ("port", "admin_port"):
        if key in sv:
            if not isinstance(sv[key], int) or isinstance(sv[key], bool) or not 1 <= sv[key] <= 65535:
                raise ConfigError(f"[server] {key} must be a port number (1-65535)")
            setattr(s.server, key, sv[key])
    if s.server.port == s.server.admin_port:
        raise ConfigError("[server] port and admin_port must be different")
    for key in ("allow_hosts", "oauth_redirect_hosts"):
        if key in sv:
            vals = _strlist("server", key, sv[key])
            if not all(HOST_RE.match(v) for v in vals):
                raise ConfigError(f"[server] {key} entries must be bare host names (no scheme, port or path)")
            setattr(s.server, key, vals)
    for key in ("oauth_enabled", "static_token_enabled", "allow_custom_commands", "wizard_done"):
        if key in sv:
            if not isinstance(sv[key], bool):
                raise ConfigError(f"[server] {key} must be true or false")
            setattr(s.server, key, sv[key])

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
            elif key in ("timeout", "start_timeout"):
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    raise ConfigError(f"[{name}] '{key}' must be a number")
                setattr(b, key, float(value))
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
    sv = {k: getattr(s.server, k) for k in sorted(_SERVER_KEYS) if getattr(s.server, k) != getattr(Server(), k)}
    if sv:
        out["server"] = sv
    out["backends"] = {n: b.to_dict() for n, b in sorted(s.backends.items()) if b.source == "config"}
    return out


def save(s: Settings, path: Path | str | None = None) -> Path:
    p = Path(path).expanduser() if path else config_path()
    private_dir(p.parent)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # private from the first byte
    with os.fdopen(fd, "w") as f:
        f.write(tomli_w.dumps(to_data(s)))
    os.chmod(tmp, 0o600)  # an old tmp file may have had other permissions
    tmp.replace(p)
    return p
