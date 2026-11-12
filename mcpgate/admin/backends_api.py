"""Backends page API: status, enable/disable, test, restart, remove."""
from __future__ import annotations

import asyncio
import dataclasses
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..backends import Backend as Conn
from ..config import NAME_RE
from . import addbackend, editbackend, friendly
from .api import body
from .app import Spec
from .context import AdminContext
from .session import AuthError


def _target(cfg) -> str:
    """Where this backend goes, without anything that could be a secret (no arguments, no query strings)."""
    if cfg.transport == "stdio":
        return cfg.command
    u = urlsplit(cfg.url)
    return f"{u.scheme}://{u.hostname or ''}{':' + str(u.port) if u.port else ''}{u.path}" if "${" not in cfg.url else cfg.url


def row(ctx: AdminContext, b) -> dict:
    cfg, pol = b.cfg, ctx.hub.policies[b.name]
    visible = hidden = None
    if b._tools is not None:
        visible = sum(1 for t in b._tools if pol.visible(t.name))
        hidden = len(b._tools) - visible
    state = "disabled" if not cfg.enabled else "connected" if b.connected else "error" if b.error else "idle"
    return {
        "name": b.name, "transport": cfg.transport, "source": cfg.source or "config", "enabled": cfg.enabled, "state": state,
        "error": ctx.secrets.scrub(b.error) if b.error and cfg.enabled else "",
        "error_hint": friendly.explain(ctx.secrets.scrub(b.error), cfg.command if cfg.transport == "stdio" else "")[1] if b.error and cfg.enabled else "",
        "tools_visible": visible, "tools_hidden": hidden, "description": cfg.description,
        "target": _target(cfg), "path": cfg.args[0] if cfg.source == "custom" and cfg.args else None,
        "readonly": cfg.source == "custom", "start_timeout": cfg.start_timeout,
        "secrets": [{"name": n, "set": ctx.secrets.has(n)} for n in sorted(cfg.secret_refs())],
        "has_policy": bool(cfg.deny or cfg.confirm or cfg.allow != ["*"]),
        "auth": cfg.auth, "signed_in": ctx.hub.oauth.signed_in(b.name) if cfg.auth == "oauth" else None,
        "signing_in": ctx.hub.oauth.pending(b.name) if cfg.auth == "oauth" else False,
    }


def routes(ctx: AdminContext) -> list[Spec]:
    def find(request: Request):
        name = request.path_params["name"]
        b = ctx.hub.backends.get(name) if NAME_RE.match(name) else None
        if b is None:
            raise AuthError(404, "no such backend")
        return b

    def need_editable(b) -> None:
        if b.cfg.source == "custom":
            raise AuthError(400, "drop-in servers are managed by their file in the custom folder")

    async def listing(request: Request) -> Response:
        rows = [row(ctx, b) for b in sorted(ctx.hub.backends.values(), key=lambda b: b.name)]
        return JSONResponse({"backends": rows, "config_error": ctx.reloader.error})

    async def set_enabled(request: Request, on: bool) -> Response:
        b = find(request)
        need_editable(b)
        if on and b.cfg.transport == "stdio" and not b.cfg.preset and not ctx.hub.settings.server.allow_custom_commands:
            raise AuthError(403, "custom command backends are switched off. Turn them on in Settings first.", extra={"switch": True})
        if on and b.cfg.transport == "stdio" and not ctx.auth.stepup_ok(request.state.session):
            return JSONResponse({"error": "re-enter your passphrase to enable a program that runs on this computer", "stepup": True}, status_code=403)

        def change(s):
            s.backends[b.name].enabled = on
        await ctx.edit(change)
        ctx.audit(event="admin_backend_enable" if on else "admin_backend_disable", backend=b.name)
        return JSONResponse(row(ctx, ctx.hub.backends[b.name]))

    async def enable(request: Request) -> Response:
        return await set_enabled(request, True)

    async def disable(request: Request) -> Response:
        return await set_enabled(request, False)

    async def test(request: Request) -> Response:
        b = find(request)
        conn, temp = b, None
        if not b.cfg.enabled:   # a throwaway connection, so testing never turns a backend on
            conn = temp = Conn(dataclasses.replace(b.cfg, enabled=True), start_timeout=b.cfg.start_timeout, secrets=ctx.secrets)
        ctx.audit(event="admin_backend_test", backend=b.name)
        try:
            tools = await asyncio.wait_for(conn.tools(refresh=True), conn.start_timeout + 5)
            visible = sum(1 for t in tools if ctx.hub.policies[b.name].visible(t.name))
            result = {"ok": True, "tools": len(tools), "visible": visible, "hidden": len(tools) - visible,
                      "names": [t.name for t in tools][:100]}
        except asyncio.TimeoutError:
            result = {"ok": False, "error": f"did not answer within {conn.start_timeout + 5:.0f} seconds",
                      "hint": "It may still be starting (the first start can download things). Try again, or allow more time when adding it."}
        except Exception as e:  # noqa: BLE001 - shown to the admin, scrubbed
            plain, hint = friendly.explain(e, b.cfg.command if b.cfg.transport == "stdio" else "")
            raw = ctx.secrets.scrub(str(e))
            result = {"ok": False, "error": ctx.secrets.scrub(plain) or raw, "hint": hint, "detail": raw[:500] if plain else ""}
        finally:
            if temp:
                await temp.stop()
        return JSONResponse({**result, "backend": row(ctx, b)})

    async def restart(request: Request) -> Response:
        b = find(request)
        if not b.cfg.enabled:
            raise AuthError(400, "this backend is disabled")
        await b.stop()
        b.error = ""
        ctx.audit(event="admin_backend_restart", backend=b.name)
        try:
            await asyncio.wait_for(b.tools(refresh=True), b.start_timeout + 5)
        except Exception:  # noqa: BLE001 - the row carries the reason
            pass
        return JSONResponse(row(ctx, b))

    def impact(b) -> dict:
        others = set()
        for o in ctx.hub.backends.values():
            if o.name != b.name:
                others |= o.cfg.secret_refs()
        only_here = sorted(n for n in b.cfg.secret_refs() - others if ctx.secrets.has(n))
        return {"has_policy": row(ctx, b)["has_policy"], "secrets_only_used_here": only_here}

    async def removal_impact(request: Request) -> Response:
        b = find(request)
        need_editable(b)
        return JSONResponse(impact(b))

    async def remove(request: Request) -> Response:
        b = find(request)
        need_editable(b)
        d = await body(request)
        if d.get("confirm") is not True:
            raise AuthError(400, "confirmation required")
        info = impact(b)

        def change(s):
            s.backends.pop(b.name, None)
        await ctx.edit(change)
        deleted = []
        if d.get("delete_secrets") is True:
            deleted = [n for n in info["secrets_only_used_here"] if ctx.secrets.delete(n)]
            await ctx.hub.apply_secret_changes()
        ctx.audit(event="admin_backend_remove", backend=b.name, secrets_deleted=deleted)
        return JSONResponse({"removed": b.name, "secrets_deleted": deleted})

    async def preset_list(request: Request) -> Response:
        out = []
        for p in addbackend.presets().values():
            fields = [{"id": f["id"], "label": f["label"], "help": f.get("help", ""), "secret_name": f["secret"],
                       "already_set": ctx.secrets.has(f["secret"])} for f in p["fields"]]
            out.append({"id": p["id"], "title": p["title"], "description": p["description"], "name": p["name"],
                        "runs_program": p["backend"]["transport"] == "stdio", "fields": fields})
        return JSONResponse({"presets": out, "custom_commands": ctx.hub.settings.server.allow_custom_commands})

    async def preview(request: Request) -> Response:
        return JSONResponse(addbackend.plan(ctx, await body(request)).view())

    async def add(request: Request) -> Response:
        d = await body(request)
        plan = addbackend.plan(ctx, d)
        if d.get("confirm") is not True:
            raise AuthError(400, "confirmation required")
        if plan.runs_program and not ctx.auth.stepup_ok(request.state.session):
            return JSONResponse({"error": "re-enter your passphrase to add a program that runs on this computer", "stepup": True}, status_code=403)
        before = {n: ctx.secrets.get(n) for n in plan.secrets}
        for n, v in plan.secrets.items():
            ctx.secrets.set(n, v)

        def change(s):
            if plan.backend.name in s.backends:
                raise AuthError(409, f"there is already a backend called {plan.backend.name}")
            s.backends[plan.backend.name] = plan.backend
        try:
            await ctx.edit(change)
        except AuthError:
            for n, old in before.items():      # put the secrets back the way they were
                ctx.secrets.set(n, old) if old else ctx.secrets.delete(n)
            raise
        ctx.audit(event="admin_backend_add", backend=plan.backend.name, kind=plan.kind, preset=plan.backend.preset,
                  secrets_stored=sorted(plan.secrets))
        return JSONResponse({"backend": row(ctx, ctx.hub.backends[plan.backend.name])})

    async def settings_get(request: Request) -> Response:
        return JSONResponse({"custom_commands": ctx.hub.settings.server.allow_custom_commands})

    async def settings_commands(request: Request) -> Response:
        d = await body(request)
        on = d.get("enabled")
        if not isinstance(on, bool):
            raise AuthError(400, "enabled must be true or false")
        if on:
            if not ctx.auth.stepup_ok(request.state.session):
                return JSONResponse({"error": "re-enter your passphrase to allow programs to be added", "stepup": True}, status_code=403)

        def change(s):
            s.server.allow_custom_commands = on
        await ctx.edit(change)
        ctx.audit(event="admin_custom_commands_on" if on else "admin_custom_commands_off")
        return JSONResponse({"custom_commands": ctx.hub.settings.server.allow_custom_commands})

    async def edit_get(request: Request) -> Response:
        b = find(request)
        need_editable(b)
        return JSONResponse(editbackend.view(ctx, b.cfg))

    async def edit_post(request: Request) -> Response:
        b = find(request)
        need_editable(b)
        d = await body(request)
        new, secrets, runs_program = editbackend.plan(ctx, b.cfg, d)
        if runs_program and not ctx.auth.stepup_ok(request.state.session):
            return JSONResponse({"error": "re-enter your passphrase to change what program runs on this computer", "stepup": True}, status_code=403)
        before = {n: ctx.secrets.get(n) for n in secrets}
        for n, v in secrets.items():
            ctx.secrets.set(n, v)

        def change(s):
            if b.name not in s.backends:
                raise AuthError(404, "that backend is not in the config file")
            s.backends[b.name] = new
        try:
            await ctx.edit(change)
        except AuthError:
            for n, old in before.items():
                ctx.secrets.set(n, old) if old else ctx.secrets.delete(n)
            raise
        restarted = await ctx.hub.apply_secret_changes()
        ctx.audit(event="admin_backend_edit", backend=b.name, fields=sorted(k for k in d if k not in ("set_secrets", "confirm")),
                  secrets_stored=sorted(secrets), restarted=restarted)
        return JSONResponse({"backend": row(ctx, ctx.hub.backends[b.name])})

    from . import signin_api
    P = "/api/backends/{name}"
    return signin_api.routes(ctx, find) + [
        Spec("/api/backends", ("GET",), listing),
        Spec("/api/presets", ("GET",), preset_list),
        Spec("/api/backends/preview", ("POST",), preview, csrf=True),
        Spec("/api/backends/add", ("POST",), add, csrf=True),
        Spec("/api/settings", ("GET",), settings_get),
        Spec("/api/settings/custom-commands", ("POST",), settings_commands, csrf=True),
        Spec(f"{P}/edit", ("GET",), edit_get),
        Spec(f"{P}/edit", ("POST",), edit_post, csrf=True),
        Spec(f"{P}/impact", ("GET",), removal_impact),
        Spec(f"{P}/enable", ("POST",), enable, csrf=True),
        Spec(f"{P}/disable", ("POST",), disable, csrf=True),
        Spec(f"{P}/test", ("POST",), test, csrf=True),
        Spec(f"{P}/restart", ("POST",), restart, csrf=True),
        Spec(f"{P}/remove", ("POST",), remove, csrf=True),
    ]
