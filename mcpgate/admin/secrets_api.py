"""Secrets page API: which secrets exist, who uses them, set/replace and delete. Values are never returned."""
from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..secretstore import NAME_RE, MAX_VALUE
from .api import body
from .app import Spec
from .context import AdminContext
from .session import AuthError


def routes(ctx: AdminContext) -> list[Spec]:
    def used_by() -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for b in ctx.hub.backends.values():
            for n in b.cfg.secret_refs():
                out.setdefault(n, []).append(b.name)
        return {k: sorted(v) for k, v in out.items()}

    async def listing(request: Request) -> Response:
        users = used_by()
        stored = {x["name"]: x["updated"] for x in ctx.secrets.names()}
        names = sorted(set(stored) | set(users))
        return JSONResponse({"secrets": [{"name": n, "set": n in stored, "updated": stored.get(n), "used_by": users.get(n, [])} for n in names]})

    def valid(request: Request) -> str:
        name = request.path_params["name"]
        if not NAME_RE.match(name):
            raise AuthError(400, "a secret name is letters, digits and '_' (it must not start with a digit)")
        return name

    async def put(request: Request) -> Response:
        name = valid(request)
        d = await body(request)
        value = d.get("value")
        if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > MAX_VALUE:
            raise AuthError(400, f"the value must be 1-{MAX_VALUE} characters")
        existed = ctx.secrets.has(name)
        ctx.secrets.set(name, value.strip())
        restarted = await ctx.hub.apply_secret_changes()
        ctx.audit(event="admin_secret_set", secret=name, replaced=existed, restarted=restarted)
        return JSONResponse({"name": name, "set": True, "restarted": restarted})

    async def delete(request: Request) -> Response:
        name = valid(request)
        d = await body(request)
        if d.get("confirm") is not True:
            raise AuthError(400, "confirmation required")
        if not ctx.secrets.delete(name):
            raise AuthError(404, "there is no stored secret with that name")
        restarted = await ctx.hub.apply_secret_changes()
        ctx.audit(event="admin_secret_delete", secret=name, restarted=restarted)
        return JSONResponse({"deleted": name, "restarted": restarted})

    return [
        Spec("/api/secrets", ("GET",), listing),
        Spec("/api/secrets/{name}", ("POST",), put, csrf=True),
        Spec("/api/secrets/{name}/delete", ("POST",), delete, csrf=True),
    ]
