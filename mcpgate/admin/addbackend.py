"""Building a new backend from what the add form sent, with the same validation whatever the form.

Nothing here trusts the browser: a preset is rebuilt from the shipped data (a request that tries to change its
command or address is refused), secret-looking values are moved to the secrets store, and a custom command
needs the feature switch."""
from __future__ import annotations

import functools
import json
import os
import re
from dataclasses import dataclass, field
from importlib import resources

from .. import config as cfgmod
from ..audit import _SECRET_KEY
from ..config import NAME_RE, Backend, ConfigError
from .session import AuthError

MAX_VALUE = 8192
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
ENVNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
PRESET_LOCKED = {"command", "args", "url", "env", "headers", "transport", "cwd", "rows"}
SECRET_ARG = re.compile(r"(token|secret|passw(or)?d|api[_-]?key)=[^$\s]", re.I)


@functools.cache
def presets() -> dict[str, dict]:
    text = resources.files("mcpgate").joinpath("data/presets.json").read_text()
    return {p["id"]: p for p in json.loads(text)["presets"]}


@dataclass
class Plan:
    backend: Backend
    secrets: dict[str, str] = field(default_factory=dict)       # name -> value to store (never shown)
    reuse: list[str] = field(default_factory=list)              # names that already have a value
    kind: str = ""

    @property
    def runs_program(self) -> bool:
        return self.backend.transport == "stdio"

    def view(self) -> dict:
        b = self.backend
        target = b.url if b.transport != "stdio" else " ".join([b.command, *b.args])
        return {"name": b.name, "kind": self.kind, "preset": b.preset, "auth": b.auth, "transport": b.transport, "target": target,
                "runs_program": self.runs_program, "description": b.description, "start_timeout": b.start_timeout,
                "cwd": b.cwd, "headers": [{"name": k, "value": v} for k, v in b.headers.items()],
                "env": [{"name": k, "value": v} for k, v in b.env.items()],
                "secrets": [{"name": n, "action": "store"} for n in sorted(self.secrets)] + [{"name": n, "action": "reuse"} for n in sorted(self.reuse)]}


def _text(v, what: str, limit: int, required: bool = True, multiline: bool = False) -> str:
    if v is None:
        v = ""
    if not isinstance(v, str):
        raise AuthError(400, f"{what} must be text")
    v = v.strip()
    if required and not v:
        raise AuthError(400, f"{what} is required")
    if len(v) > limit or "\x00" in v or (not multiline and ("\n" in v or "\r" in v)):
        raise AuthError(400, f"{what} is not valid")
    return v


def _number(v, what: str, default: float, lo: float = 1, hi: float = 300) -> float:
    if v in (None, ""):
        return default
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise AuthError(400, f"{what} must be a number between {lo:g} and {hi:g}")
    return float(v)


def _list(v, what: str, limit: int) -> list:
    if v in (None, ""):
        return []
    if not isinstance(v, list) or len(v) > limit:
        raise AuthError(400, f"{what} must be a list of at most {limit} entries")
    return v


class Builder:
    def __init__(self, ctx):
        self.ctx = ctx
        self.taken = set(ctx.hub.backends) | set(ctx.file_settings().backends)
        self.used_secrets: dict[str, set[str]] = {}
        for b in ctx.hub.backends.values():
            for n in b.cfg.secret_refs():
                self.used_secrets.setdefault(n, set()).add(b.name)

    # -- shared pieces ------------------------------------------------------------
    def name(self, d: dict, default: str = "") -> str:
        name = _text(d.get("name") or default, "the name", 64)
        if not NAME_RE.match(name):
            raise AuthError(400, "the name must be lowercase letters, digits, '-' or '_' (at most 32 characters)")
        if name in self.taken:
            raise AuthError(409, f"there is already a backend called {name}")
        return name

    def secret_name(self, plan: Plan, backend: str, row: str) -> str:
        base = re.sub(r"[^A-Z0-9_]", "_", f"{backend}_{row}".upper())
        base = base if not base[0].isdigit() else "_" + base
        for i in range(1, 10):
            cand = base if i == 1 else f"{base}_{i}"
            if cand not in plan.secrets and not self.used_secrets.get(cand):   # an orphaned value may be replaced
                return cand
        raise AuthError(409, "too many secrets with that name")

    def rows(self, plan: Plan, d_rows, what: str, name_re, limit: int) -> dict[str, str]:
        out: dict[str, str] = {}
        for row in _list(d_rows, what, limit):
            if not isinstance(row, dict):
                raise AuthError(400, f"each {what} entry needs a name and a value")
            rname = _text(row.get("name"), f"a {what} name", 64)
            if not name_re.match(rname) or rname in out:
                raise AuthError(400, f"{rname!r} is not a valid, unique {what} name")
            value = _text(row.get("value"), f"the value of {rname}", MAX_VALUE, required=False)
            flagged = row.get("secret") is True
            if flagged and not value:
                raise AuthError(400, f"{rname} is marked secret, so it needs a value")
            if flagged or (value and _SECRET_KEY.search(rname) and "${" not in value):
                sname = self.secret_name(plan, plan.backend.name, rname)   # moved out of the config automatically
                plan.secrets[sname] = value
                value = "${" + sname + "}"
            out[rname] = value
        return out

    def finish(self, plan: Plan) -> Plan:
        b = plan.backend
        try:
            if b.transport != "stdio":
                b.url = cfgmod.check_backend_url(b.url)
            b.validate()
        except ConfigError as e:
            raise AuthError(400, str(e)) from None
        return plan

    # -- the three kinds ------------------------------------------------------------
    def preset(self, d: dict) -> Plan:
        p = presets().get(d.get("preset"))
        if p is None:
            raise AuthError(400, "unknown preset")
        locked = PRESET_LOCKED & set(d)
        if locked:
            raise AuthError(400, f"a preset's {', '.join(sorted(locked))} cannot be changed; it is rebuilt from the preset")
        b = Backend(name=self.name(d, p["name"]), preset=p["id"], **json.loads(json.dumps(p["backend"])))
        if "description" in d:
            b.description = _text(d["description"], "the description", 200, required=False)
        plan = Plan(b, kind="preset")
        values = d.get("values") or {}
        if not isinstance(values, dict):
            raise AuthError(400, "values must be an object")
        for f in p["fields"]:
            secret = f["secret"]
            given = _text(values.get(f["id"]), f["label"], MAX_VALUE, required=False)
            if given:
                if re.search(r"\s", given):
                    raise AuthError(400, f"{f['label']} must not contain spaces")
                plan.secrets[secret] = given
            elif self.ctx.secrets.has(secret) or os.environ.get(secret):
                plan.reuse.append(secret)
            else:
                raise AuthError(400, f"{f['label']} is required")
        return self.finish(plan)

    def remote(self, d: dict) -> Plan:
        transport = d.get("transport", "http")
        if transport not in ("http", "sse"):
            raise AuthError(400, "the transport must be http or sse")
        b = Backend(name=self.name(d), transport=transport, url=_text(d.get("url"), "the address", 2000),
                    description=_text(d.get("description"), "the description", 200, required=False),
                    start_timeout=_number(d.get("start_timeout"), "the start timeout", 30.0))
        plan = Plan(b, kind="remote")
        auth = d.get("auth", "")
        if auth not in ("", "oauth"):
            raise AuthError(400, "auth must be oauth or left out")
        b.auth = auth
        b.headers = self.rows(plan, d.get("headers"), "header", HEADER_RE, 30)
        return self.finish(plan)

    def command(self, d: dict) -> Plan:
        if not self.ctx.hub.settings.server.allow_custom_commands:
            raise AuthError(403, "custom command backends are switched off. Turn them on in Settings first.", extra={"switch": True})
        args = [_text(a, "an argument", 1000, required=False) for a in _list(d.get("args"), "the arguments", 50)]
        for a in args:
            if SECRET_ARG.search(a):
                raise AuthError(400, "an argument looks like it contains a secret; pass secrets as environment values marked secret")
        b = Backend(name=self.name(d), transport="stdio", command=_text(d.get("command"), "the command", 500), args=args,
                    cwd=_text(d.get("cwd"), "the working directory", 500, required=False),
                    description=_text(d.get("description"), "the description", 200, required=False),
                    start_timeout=_number(d.get("start_timeout"), "the start timeout", 30.0))
        plan = Plan(b, kind="command")
        b.env = self.rows(plan, d.get("env"), "environment", ENVNAME_RE, 50)
        return self.finish(plan)


def plan(ctx, d: dict) -> Plan:
    kind = d.get("kind")
    build = Builder(ctx)
    if kind == "preset":
        return build.preset(d)
    if kind == "remote":
        return build.remote(d)
    if kind == "command":
        return build.command(d)
    raise AuthError(400, "unknown kind of backend")
