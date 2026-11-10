"""First-run setup guide: whether it is done, how local clients connect, and what ends up protected or exposed."""
from __future__ import annotations

import json
import shlex

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .. import config as cfgmod
from .. import remote
from .api import body
from .app import Spec
from .context import AdminContext
from .session import AuthError


def routes(ctx: AdminContext) -> list[Spec]:
    def connect() -> dict:
        env = {}
        if ctx.config_file and str(ctx.config_file) != str(cfgmod.config_path()):
            env["MCPGATE_CONFIG"] = str(ctx.config_file)
        cmd = "claude mcp add mcpgate" + "".join(f" -e {shlex.quote(k + '=' + v)}" for k, v in env.items()) + " -- mcpgate serve"
        snippet = {"mcpServers": {"mcpgate": {"command": "mcpgate", "args": ["serve"], **({"env": env} if env else {})}}}
        return {"command": cmd, "json": json.dumps(snippet, indent=2)}

    def summary() -> dict:
        s = ctx.file_settings()
        backends = []
        for name, b in sorted(s.backends.items()):
            live = ctx.hub.backends.get(name)
            backends.append({"name": name, "transport": b.transport, "enabled": b.enabled, "needs_approval": len(b.confirm), "blocked": len(b.deny),
                             "secrets": [{"name": n, "set": ctx.secrets.has(n)} for n in sorted(b.secret_refs())],
                             "connected": bool(live and live.connected)})
        w = remote.wanted(s, ctx.auth.store, ctx.env_token, ctx.env_pass)
        return {"admin": {"address": f"127.0.0.1:{s.server.admin_port}"},
                "backends": backends,
                "approvals": ctx.hub.approvals is not None,
                "remote": {"exposed": bool(w["listener"]), "public_url": s.server.public_url if w["oauth"] else "", "signs_in": w["oauth"], "token": w["static"]},
                "audit": bool(s.audit_log)}

    async def show(request: Request) -> Response:
        s = ctx.file_settings()
        return JSONResponse({"done": s.server.wizard_done, "has_backend": bool(s.backends), "connect": connect(), "summary": summary()})

    async def mark(request: Request) -> Response:
        d = await body(request)
        if set(d) != {"done"} or not isinstance(d["done"], bool):
            raise AuthError(400, "send done as true or false")
        await ctx.edit(lambda s: setattr(s.server, "wizard_done", d["done"]))
        return JSONResponse({"done": d["done"]})

    return [Spec("/api/wizard", ("GET",), show), Spec("/api/wizard", ("POST",), mark, csrf=True)]
