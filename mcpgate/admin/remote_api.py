"""Remote access page API: public address, sign-in secrets, connection check, signed-in apps, restart."""
from __future__ import annotations

import asyncio
import re
import time

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .. import remote
from ..authstore import MIN_PASSPHRASE, new_token
from ..config import ConfigError
from .api import body
from .app import Spec
from .context import AdminContext
from .session import AuthError

ID_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
CHECK_GAP = 3.0   # seconds between connection checks


def routes(ctx: AdminContext) -> list[Spec]:
    def stepup(request: Request, why: str):
        if not ctx.auth.stepup_ok(request.state.session):
            return JSONResponse({"error": f"re-enter your passphrase {why}", "stepup": True}, status_code=403)
        return None

    def state() -> dict:
        s = ctx.file_settings()
        srv = s.server
        store = ctx.auth.store
        w = remote.wanted(s, store, ctx.env_token, ctx.env_pass)
        oauth = ctx.oauth_store()
        names = {c["client_id"]: c for c in oauth.clients()}
        sessions = oauth.sessions()
        clients = []
        for cid, c in names.items():
            mine = [x for x in sessions if x["client_id"] == cid]
            clients.append({**c, "sessions": len(mine), "last_used": max([x["last_used"] for x in mine] or [0])})
        return {
            "settings": {"public_url": srv.public_url, "port": srv.port, "allow_hosts": srv.allow_hosts, "oauth_enabled": srv.oauth_enabled,
                         "static_token_enabled": srv.static_token_enabled, "admin_port": srv.admin_port},
            "passphrase": {"set": store.has("oauth_passphrase"), "from_env": ctx.env_pass, "updated": store.when("oauth_passphrase")},
            "token": {"set": store.has("static_token"), "from_env": ctx.env_token, "updated": store.when("static_token")},
            "instructions": remote.instructions(srv.public_url, srv.port),
            "clients": sorted(clients, key=lambda c: -c["last_used"]), "sessions": sessions,
            "restart": {"required": ctx.running is not None and w != ctx.running, "service": ctx.running is not None,
                        "supervised": remote.supervised() and ctx.restarter is not None,
                        "listening": bool(ctx.running and ctx.running.get("listener"))},
            "ready": {"oauth": w["oauth"], "static": w["static"]},
        }

    async def show(request: Request) -> Response:
        return JSONResponse(state())

    async def save_settings(request: Request) -> Response:
        d = await body(request)
        srv = ctx.file_settings().server
        try:
            clean = remote.validate_settings(d, srv.admin_port)
        except ConfigError as e:
            raise AuthError(400, str(e)) from None
        if (clean.get("oauth_enabled", srv.oauth_enabled)) and not clean.get("public_url", srv.public_url):
            raise AuthError(400, "remote sign-in needs a public address")
        if not clean:
            raise AuthError(400, "nothing to change")

        def change(s):
            for k, v in clean.items():
                setattr(s.server, k, v)
        await ctx.edit(change)
        ctx.audit(event="admin_remote_settings", changed=clean)
        return JSONResponse(state())

    async def passphrase(request: Request) -> Response:
        if (r := stepup(request, "to change the approval passphrase")):
            return r
        d = await body(request)
        pw, keep = d.get("passphrase"), d.get("keep_sessions", True)
        if not isinstance(pw, str) or len(pw) < MIN_PASSPHRASE:
            raise AuthError(400, f"the passphrase must be at least {MIN_PASSPHRASE} characters")
        if not isinstance(keep, bool):
            raise AuthError(400, "keep_sessions must be true or false")
        try:
            ctx.auth.store.set_passphrase("oauth_passphrase", pw)
        except ConfigError as e:
            raise AuthError(400, str(e)) from None
        if not keep:
            ctx.oauth_store().clear()
        ctx.audit(event="admin_oauth_passphrase_changed", signed_everyone_out=not keep)
        return JSONResponse(state())

    async def token_create(request: Request) -> Response:
        if (r := stepup(request, "to create a token")):
            return r
        token = new_token()
        ctx.auth.store.set_token("static_token", token)
        await ctx.edit(lambda s: setattr(s.server, "static_token_enabled", True))
        ctx.audit(event="admin_token_created")
        return JSONResponse({**state(), "token": token})        # the only time it is ever sent

    async def token_remove(request: Request) -> Response:
        ctx.auth.store.clear("static_token")
        ctx.audit(event="admin_token_removed")
        return JSONResponse(state())

    async def check(request: Request) -> Response:
        url = ctx.file_settings().server.public_url
        if not url:
            raise AuthError(400, "save a public address first")
        async with ctx.check_lock:
            wait = CHECK_GAP - (time.monotonic() - ctx.last_check)
            if wait > 0:
                raise AuthError(429, f"checked a moment ago; try again in {int(wait) + 1} seconds", int(wait) + 1)
            ctx.last_check = time.monotonic()
            try:
                results = await remote.check(url, transport=ctx.check_transport, resolve=ctx.resolve)
            except ConfigError as e:
                raise AuthError(400, str(e)) from None
        ctx.audit(event="admin_remote_check", ok=all(r["ok"] is not False for r in results))
        return JSONResponse({"url": url, "results": results, "restart_required": state()["restart"]["required"]})

    def ident(request: Request, key: str) -> str:
        v = request.path_params[key]
        if not ID_RE.match(v):
            raise AuthError(404, "not found")
        return v

    async def signout(request: Request) -> Response:
        sid = ident(request, "sid")
        if not ctx.oauth_store().signout(sid):
            raise AuthError(404, "that session is already gone")
        ctx.audit(event="admin_signout_session")
        return JSONResponse(state())

    async def remove_client(request: Request) -> Response:
        cid = ident(request, "cid")
        if not ctx.oauth_store().remove_client(cid):
            raise AuthError(404, "that app is already gone")
        ctx.audit(event="admin_remove_app")
        return JSONResponse(state())

    async def signout_all(request: Request) -> Response:
        ctx.oauth_store().clear()
        ctx.audit(event="admin_signout_all")
        return JSONResponse(state())

    async def restart(request: Request) -> Response:
        if (r := stepup(request, "to restart the service")):
            return r
        if ctx.restarter is None:
            raise AuthError(409, "this gateway was not started as the service, so it cannot be restarted from here")
        if not remote.supervised():
            raise AuthError(409, "mcpgate is not running under a service manager, so nothing would start it again. "
                                 "Stop it (Ctrl+C) and run it again yourself.")
        ctx.audit(event="admin_restart")
        asyncio.get_running_loop().call_later(0.7, ctx.restarter.trigger)   # after this answer has been sent
        return JSONResponse({"restarting": True})

    P = "/api/remote"
    return [
        Spec(P, ("GET",), show),
        Spec(P + "/settings", ("POST",), save_settings, csrf=True),
        Spec(P + "/passphrase", ("POST",), passphrase, csrf=True),
        Spec(P + "/token", ("POST",), token_create, csrf=True),
        Spec(P + "/token/remove", ("POST",), token_remove, csrf=True),
        Spec(P + "/check", ("POST",), check, csrf=True),
        Spec(P + "/sessions/{sid}/signout", ("POST",), signout, csrf=True),
        Spec(P + "/clients/{cid}/remove", ("POST",), remove_client, csrf=True),
        Spec(P + "/signout-all", ("POST",), signout_all, csrf=True),
        Spec(P + "/restart", ("POST",), restart, csrf=True),
    ]
