"""Sign in to a remote backend that uses an account instead of a token (see backend_oauth.py)."""
from __future__ import annotations

import html

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

from ..backend_oauth import SignInRequired
from ..config import expand
from .app import Spec
from .context import AdminContext
from .session import AuthError


def routes(ctx: AdminContext, find) -> list[Spec]:
    def need_oauth(b) -> None:
        if b.cfg.transport == "stdio" or b.cfg.auth != "oauth":
            raise AuthError(400, "this backend is not set up to sign in. Open Edit and tick \"This server needs me to sign in\".")

    async def signin(request: Request) -> Response:
        b = find(request)
        need_oauth(b)
        cfg = b.cfg
        lookup = ctx.secrets.get
        headers = {k: expand(v, lookup=lookup) for k, v in cfg.headers.items()}

        async def done() -> None:
            ctx.audit(event="admin_backend_signin_done", backend=b.name)
            conn = ctx.hub.backends.get(b.name)
            if conn is not None and conn.cfg.enabled:
                await conn.stop()
                try:
                    await conn.ensure()
                except Exception:  # noqa: BLE001 - the card shows the reason
                    pass

        try:
            url = await ctx.hub.oauth.begin(b.name, cfg.transport, expand(cfg.url, lookup=lookup), headers, done)
        except SignInRequired as e:
            raise AuthError(502, ctx.secrets.scrub(str(e))) from None
        except Exception as e:  # noqa: BLE001
            raise AuthError(502, ctx.secrets.scrub(f"could not reach the server: {e}")) from None
        ctx.audit(event="admin_backend_signin_start", backend=b.name, already=url is None)
        if url is None:
            await done()
            return JSONResponse({"already": True})
        return JSONResponse({"url": url, "redirect_uri": ctx.hub.oauth.redirect_uri()})

    async def signout(request: Request) -> Response:
        b = find(request)
        need_oauth(b)
        had = ctx.hub.oauth.forget(b.name)
        await b.stop()
        ctx.audit(event="admin_backend_signout", backend=b.name, had_tokens=had)
        return JSONResponse({"signed_out": had})

    async def callback(request: Request) -> Response:
        q = request.query_params
        name = ctx.hub.oauth.finish(q.get("state", ""), q.get("code"), q.get("error"))
        if name is None:
            body = ("<h1>This sign-in link is not valid</h1><p>It may have expired or already been used. "
                    "Go back to mcpgate and press Sign in again.</p>")
            status = 400
        elif q.get("error"):
            body = f"<h1>Sign-in was not completed</h1><p>The server said: {html.escape(q.get('error', '')[:200])}.</p>"
            status = 400
        else:
            body = f"<h1>Signed in to {html.escape(name)}</h1><p>You can close this tab and go back to mcpgate.</p>"
            status = 200
        page = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                "<title>mcpgate sign-in</title><link rel=\"stylesheet\" href=\"/static/app.css\"></head><body><main>" + body +
                "<p><a href=\"/#/backends\">Back to mcpgate</a></p></main></body></html>")
        return HTMLResponse(page, status_code=status, headers={"referrer-policy": "no-referrer"})

    P = "/api/backends/{name}"
    return [
        Spec(f"{P}/signin", ("POST",), signin, csrf=True),
        Spec(f"{P}/signout", ("POST",), signout, csrf=True),
        Spec("/oauth/callback", ("GET",), callback, session=False),
    ]
