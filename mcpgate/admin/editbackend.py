"""Changing an existing backend, and replacing the secrets it uses, without removing it.

The same rules as adding one: values that look like secrets are moved to the secrets store, a preset's command and
address cannot be changed, and anything that changes what program runs needs the passphrase again. Secret values
are write-only: the editor shows that one is stored, never what it is."""
from __future__ import annotations

import dataclasses
import re

from .. import config as cfgmod
from ..audit import _SECRET_KEY
from ..config import ENV_RE, ConfigError
from ..secretstore import NAME_RE as SECRET_NAME_RE
from .addbackend import (ENVNAME_RE, HEADER_RE, MAX_VALUE, PRESET_LOCKED, SECRET_ARG, _list, _number, _text)
from .session import AuthError

PRESET_EDITABLE = {"description", "set_secrets"}
EDITABLE = {"description", "start_timeout", "url", "headers", "auth", "command", "args", "cwd", "env", "set_secrets"}
EXACT_REF = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def view(ctx, cfg) -> dict:
    """What the editor shows. A value that is exactly ${NAME} is a stored secret: only its name and whether
    it has a value are returned."""
    def rows(d: dict[str, str]) -> list[dict]:
        out = []
        for k, v in d.items():
            m = EXACT_REF.match(v)
            out.append({"name": k, "value": "" if m else v, "secret": m.group(1) if m else "", "set": bool(m and (ctx.secrets.has(m.group(1))))})
        return out
    stdio = cfg.transport == "stdio"
    return {"name": cfg.name, "transport": cfg.transport, "preset": cfg.preset, "description": cfg.description,
            "start_timeout": cfg.start_timeout, "auth": cfg.auth, "url": cfg.url if not stdio else "", "headers": rows(cfg.headers),
            "command": cfg.command, "args": list(cfg.args), "cwd": cfg.cwd, "env": rows(cfg.env),
            "runs_program": stdio, "editable": sorted(PRESET_EDITABLE if cfg.preset else EDITABLE),
            "secrets": [{"name": n, "set": ctx.secrets.has(n)} for n in sorted(cfg.secret_refs())]}


def _new_secret_name(used: set[str], backend: str, row: str) -> str:
    base = re.sub(r"[^A-Z0-9_]", "_", f"{backend}_{row}".upper())
    base = base if not base[0].isdigit() else "_" + base
    for i in range(1, 20):
        cand = base if i == 1 else f"{base}_{i}"
        if cand not in used:
            return cand
    raise AuthError(409, "too many secrets with that name")


def _rows(d_rows, what: str, name_re, limit: int, backend: str, taken: set[str], new_secrets: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for row in _list(d_rows, what, limit):
        if not isinstance(row, dict):
            raise AuthError(400, f"each {what} entry needs a name and a value")
        rname = _text(row.get("name"), f"a {what} name", 64)
        if not name_re.match(rname) or rname in out:
            raise AuthError(400, f"{rname!r} is not a valid, unique {what} name")
        ref = row.get("secret") if isinstance(row.get("secret"), str) else ""
        value = _text(row.get("value"), f"the value of {rname}", MAX_VALUE, required=False)
        if ref:                                         # an existing stored secret, kept (its value is replaced via set_secrets)
            if not SECRET_NAME_RE.match(ref):
                raise AuthError(400, "that secret name is not valid")
            out[rname] = "${" + ref + "}"
            continue
        if row.get("secret") is True or (value and _SECRET_KEY.search(rname) and "${" not in value):
            if not value:
                raise AuthError(400, f"{rname} is marked secret, so it needs a value")
            sname = _new_secret_name(taken | set(new_secrets), backend, rname)
            new_secrets[sname] = value
            value = "${" + sname + "}"
        out[rname] = value
    return out


def plan(ctx, cfg, d: dict) -> tuple[object, dict[str, str], bool]:
    """Returns (the new backend settings, secret values to store, whether it changes what program runs)."""
    if not isinstance(d, dict):
        raise AuthError(400, "send an object")
    unknown = set(d) - EDITABLE - {"confirm"}
    if unknown:
        raise AuthError(400, f"unknown field: {sorted(unknown)[0]}")
    if cfg.preset:
        locked = (PRESET_LOCKED | {"start_timeout"}) & set(d)
        if locked:
            raise AuthError(400, f"a preset's {', '.join(sorted(locked))} cannot be changed; only its description and secrets can")
    stdio = cfg.transport == "stdio"
    for key in ("url", "headers", "auth") if stdio else ("command", "args", "cwd", "env"):
        if key in d:
            raise AuthError(400, f"a {cfg.transport} backend has no {key}")
    new = dataclasses.replace(cfg, args=list(cfg.args), env=dict(cfg.env), headers=dict(cfg.headers), allow=list(cfg.allow),
                              deny=list(cfg.deny), confirm=list(cfg.confirm))
    taken = set()
    for o in ctx.hub.backends.values():
        taken |= o.cfg.secret_refs() if o.name != cfg.name else set()
    taken |= {n["name"] for n in ctx.secrets.names()}
    new_secrets: dict[str, str] = {}
    runs_program = False
    if "description" in d:
        new.description = _text(d["description"], "the description", 200, required=False)
    if "start_timeout" in d:
        new.start_timeout = _number(d["start_timeout"], "the start timeout", cfg.start_timeout)
    if "url" in d:
        new.url = _text(d["url"], "the address", 2000)
    if "auth" in d:
        if d["auth"] not in ("", "oauth"):
            raise AuthError(400, "auth must be oauth or left out")
        new.auth = d["auth"]
    if "headers" in d:
        new.headers = _rows(d["headers"], "header", HEADER_RE, 30, cfg.name, taken, new_secrets)
    if "command" in d:
        new.command = _text(d["command"], "the command", 500)
        runs_program |= new.command != cfg.command
    if "args" in d:
        args = [_text(a, "an argument", 1000, required=False) for a in _list(d["args"], "the arguments", 50)]
        for a in args:
            if SECRET_ARG.search(a):
                raise AuthError(400, "an argument looks like it contains a secret; pass secrets as environment values marked secret")
        new.args = args
        runs_program |= args != cfg.args
    if "cwd" in d:
        new.cwd = _text(d["cwd"], "the working directory", 500, required=False)
        runs_program |= new.cwd != cfg.cwd
    if "env" in d:
        new.env = _rows(d["env"], "environment", ENVNAME_RE, 50, cfg.name, taken, new_secrets)
        runs_program |= new.env != cfg.env
    if runs_program and not ctx.hub.settings.server.allow_custom_commands and not cfg.preset:
        raise AuthError(403, "programs that run on this computer are switched off. Turn them on in Settings first.", extra={"switch": True})
    try:
        if not stdio:
            new.url = cfgmod.check_backend_url(new.url)
        new.validate()
    except ConfigError as e:
        raise AuthError(400, str(e)) from None
    sets = d.get("set_secrets") or {}
    if not isinstance(sets, dict) or len(sets) > 50:
        raise AuthError(400, "set_secrets must be an object")
    refs = new.secret_refs()
    for name, value in sets.items():
        if name not in refs and name not in new_secrets:
            raise AuthError(400, f"{name} is not used by this backend")
        if not isinstance(value, str) or not value.strip():
            raise AuthError(400, f"the value of {name} is empty")
        new_secrets[name] = value.strip()
    for name, value in new_secrets.items():
        if not SECRET_NAME_RE.match(name) or len(value) > MAX_VALUE or "\x00" in value:
            raise AuthError(400, f"the value of {name} is not valid")
    return new, new_secrets, runs_program
