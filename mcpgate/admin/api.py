"""Admin API routes for login, setup and session state. Handlers return JSON and never echo secrets."""
from __future__ import annotations

import json

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .app import Spec
from .session import COOKIE, AdminAuth, AuthError

MAX_BODY = 16 * 1024


async def body(request: Request) -> dict:
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise AuthError(415, "send JSON")
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise AuthError(413, "request too large")
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        raise AuthError(400, "invalid JSON") from None
    if not isinstance(data, dict):
        raise AuthError(400, "expected a JSON object")
    return data


def fail(e: AuthError) -> Response:
    headers = {"retry-after": str(e.retry_after)} if e.retry_after else {}
    return JSONResponse({"error": e.message, **e.extra}, status_code=e.status, headers=headers)


def with_cookie(resp: Response, cookie: str) -> Response:
    resp.set_cookie(COOKIE, cookie, httponly=True, samesite="strict", path="/")   # a session cookie: no expiry date
    return resp


def routes(auth: AdminAuth) -> list[Spec]:
    def info(sess) -> dict:
        if sess is None:
            return {"state": auth.state()}
        return {"state": "ready", "csrf": sess.csrf, "stepup": auth.stepup_ok(sess)}

    async def session(request: Request) -> Response:
        return JSONResponse(info(auth.get(request.cookies.get(COOKIE))))

    async def setup(request: Request) -> Response:
        try:
            d = await body(request)
            cookie, sess = auth.setup(d.get("code"), d.get("passphrase"))
        except AuthError as e:
            return fail(e)
        return with_cookie(JSONResponse(info(sess)), cookie)

    async def login(request: Request) -> Response:
        try:
            cookie, sess = auth.login((await body(request)).get("passphrase"))
        except AuthError as e:
            return fail(e)
        return with_cookie(JSONResponse(info(sess)), cookie)

    async def logout(request: Request) -> Response:
        auth.logout(request.cookies.get(COOKIE))
        resp = JSONResponse({"state": auth.state()})
        resp.delete_cookie(COOKIE, path="/")
        return resp

    async def stepup(request: Request) -> Response:
        try:
            auth.stepup(request.state.session, (await body(request)).get("passphrase"))
        except AuthError as e:
            return fail(e)
        return JSONResponse(info(request.state.session))

    async def passphrase(request: Request) -> Response:
        try:
            d = await body(request)
            cookie, sess = auth.change_passphrase(request.state.session, d.get("current"), d.get("new"))
        except AuthError as e:
            return fail(e)
        return with_cookie(JSONResponse(info(sess)), cookie)

    return [
        Spec("/api/session", ("GET",), session, session=False),
        Spec("/api/setup", ("POST",), setup, session=False),     # no session exists yet; protected by the one-time code
        Spec("/api/login", ("POST",), login, session=False),     # no session exists yet; protected by the passphrase
        Spec("/api/logout", ("POST",), logout, session=True, csrf=True),
        Spec("/api/stepup", ("POST",), stepup, session=True, csrf=True),
        Spec("/api/passphrase", ("POST",), passphrase, session=True, csrf=True),
    ]
