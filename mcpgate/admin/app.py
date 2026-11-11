"""Admin web app: a small Starlette app plus the guards that keep it local-only.

Rules enforced here (see SECURITY.md once it exists):
* every request must carry a loopback Host header and no proxy/tunnel headers, so a tunnel
  pointed at this port by mistake cannot serve it;
* every response carries a strict CSP (no inline script, no outside resources) and no-store caching;
* every state-changing request needs an Origin that matches the Host;
* routes are declared in ROUTES with whether they need a session / CSRF token, so tests can check
  the whole table instead of trusting each handler.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

ADMIN_HOST = "127.0.0.1"   # deliberately a constant: there is no setting, flag or env var for it
STATIC = Path(__file__).parent / "static"
SAFE_METHODS = {"GET", "HEAD"}
BLOCKED_HEADER_PREFIXES = ("x-forwarded-", "x-real-ip", "cf-", "tailscale-", "x-tailscale-", "cdn-loop", "true-client-ip")
BLOCKED_HEADERS = {"forwarded", "via"}

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "content-security-policy": CSP,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}


class AdminError(RuntimeError):
    pass


@dataclass(frozen=True)
class Spec:
    """One admin route and the protections it must have."""
    path: str
    methods: tuple[str, ...]
    handler: Callable[[Request], Awaitable[Response]]
    session: bool = True      # needs a logged-in admin session (enforced from the session layer on)
    csrf: bool = False        # needs the CSRF token header (all state-changing routes)

    @property
    def state_changing(self) -> bool:
        return any(m not in SAFE_METHODS for m in self.methods)


def allowed_hosts(port: int) -> set[str]:
    return {f"127.0.0.1:{port}", f"localhost:{port}"}


class Guard:
    """Pure ASGI middleware: host and proxy-header checks, Origin check, security headers."""

    def __init__(self, app, port: int):
        self.app, self.hosts = app, allowed_hosts(port)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":   # no websockets, no lifespan surprises
            if scope["type"] == "lifespan":
                return await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        problem = self._check(scope["method"], headers)
        if problem:
            return await self._reply(send, problem[0], problem[1])

        async def send_with_headers(msg):
            if msg["type"] == "http.response.start":
                have = {k.lower() for k, _ in msg["headers"]}
                msg["headers"] = list(msg["headers"]) + [(k.encode(), v.encode()) for k, v in SECURITY_HEADERS.items() if k.encode() not in have]
            await send(msg)
        await self.app(scope, receive, send_with_headers)

    def _check(self, method: str, h: dict[str, str]):
        if h.get("host", "") not in self.hosts:
            return 400, "unexpected Host header"
        for name in h:
            if name in BLOCKED_HEADERS or name.startswith(BLOCKED_HEADER_PREFIXES):
                return 400, "proxied requests are not accepted"
        if method not in SAFE_METHODS:
            origin = h.get("origin")
            if origin not in {f"http://{x}" for x in (h["host"],)}:
                return 403, "bad Origin"
        return None

    async def _reply(self, send, status: int, text: str):
        body = text.encode()
        headers = [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode())]
        headers += [(k.encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


# -- handlers -------------------------------------------------------------------
async def health(request: Request) -> Response:
    return JSONResponse({"ok": True})


def _static(name: str, media: str):
    async def handler(request: Request) -> Response:
        return Response((STATIC / name).read_bytes(), media_type=media)
    return handler


ROUTES: list[Spec] = [
    Spec("/", ("GET",), _static("index.html", "text/html; charset=utf-8"), session=False),
    Spec("/static/app.js", ("GET",), _static("app.js", "text/javascript; charset=utf-8"), session=False),
    Spec("/static/app.css", ("GET",), _static("app.css", "text/css; charset=utf-8"), session=False),
    Spec("/api/health", ("GET",), health, session=False),
]


# State-changing routes that cannot require a session (there is none yet); each is protected by a credential instead.
PRE_AUTH = {"/api/setup", "/api/login"}


def _enforced(spec: Spec, auth):
    """Wrap a handler so the session and CSRF rules declared in its Spec are applied here, not left to the handler."""
    from .api import fail
    from .session import COOKIE, AuthError

    async def handler(request: Request) -> Response:
        request.state.session = None
        try:
            return await _run(request)
        except AuthError as e:
            return fail(e)

    async def _run(request: Request) -> Response:
        if spec.session:
            sess = auth.get(request.cookies.get(COOKIE)) if auth else None
            if sess is None:
                return JSONResponse({"error": "login required"}, status_code=401)
            if spec.csrf and not auth.csrf_ok(sess, request.headers.get("x-csrf-token", "")):
                return JSONResponse({"error": "bad CSRF token"}, status_code=403)
            request.state.session = sess
        return await spec.handler(request)
    return handler


def make_app(port: int, extra: list[Spec] | None = None, auth=None, ctx=None) -> Starlette:
    specs = ROUTES + list(extra or [])
    if auth is not None:
        from .api import routes as api_routes
        specs += api_routes(auth)
    if ctx is not None:
        from .backends_api import routes as backend_routes
        specs += backend_routes(ctx)
        from .policy_api import routes as policy_routes
        specs += policy_routes(ctx)
        from .approvals_api import routes as approval_routes
        specs += approval_routes(ctx)
        from .remote_api import routes as remote_routes
        specs += remote_routes(ctx)
        from .audit_api import routes as audit_routes
        specs += audit_routes(ctx)
        from .wizard_api import routes as wizard_routes
        specs += wizard_routes(ctx)
        from .secrets_api import routes as secret_routes
        specs += secret_routes(ctx)
    routes = [Route(s.path, _enforced(s, auth), methods=list(s.methods)) for s in specs]

    async def not_found(request, exc):
        return PlainTextResponse("not found", status_code=404)

    app = Starlette(routes=routes, exception_handlers={404: not_found, 405: not_found})
    app.state.specs = specs
    return Guard(app, port)


def bind(port: int) -> socket.socket:
    """Bind the admin port on loopback. If that fails the UI does not start; it never picks another address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ADMIN_HOST, port))
    except OSError as e:
        sock.close()
        raise AdminError(f"the admin UI could not listen on {ADMIN_HOST}:{port} ({e.strerror}); it will not start elsewhere") from None
    return sock


class AdminServer:
    def __init__(self, port: int, extra: list[Spec] | None = None, auth=None, ctx=None):
        self.port = port
        self.sock = bind(port)
        self.server = uvicorn.Server(uvicorn.Config(make_app(port, extra, auth, ctx), log_level="warning", lifespan="off"))

    async def serve(self) -> None:
        await self.server.serve(sockets=[self.sock])

    def stop(self) -> None:
        self.server.should_exit = True
