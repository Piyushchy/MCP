"""Running the gateway: over stdio (a client starts it) or over HTTP (reachable from elsewhere)."""
from __future__ import annotations

import asyncio
import hmac
import ipaddress

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .hub import Hub

MIN_TOKEN = 24


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def transport_security(allow_hosts: list[str]) -> TransportSecuritySettings | None:
    """Host headers accepted by the HTTP server (needed behind a tunnel or proxy that rewrites Host)."""
    if not allow_hosts:
        return None
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    for h in allow_hosts:
        hosts += [h, f"{h}:*"]
    return TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts)


class BearerAuth:
    """ASGI wrapper: every HTTP request must carry 'Authorization: Bearer <token>'."""

    def __init__(self, app, token: str | None = None, verify=None):
        """Give the plain ``token`` (from the environment) or a ``verify(candidate) -> bool`` callable (hashed)."""
        if verify is None:
            if token is None or len(token) < MIN_TOKEN:
                raise ValueError(f"token must be at least {MIN_TOKEN} characters (try: mcpgate token)")
            self.token = token.encode()
            verify = lambda given: hmac.compare_digest(given.encode(), self.token)  # noqa: E731
        self.app, self.verify = app, verify

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":  # lifespan etc. pass straight through
            return await self.app(scope, receive, send)
        auth = dict(scope["headers"]).get(b"authorization", b"")
        scheme, _, given = auth.partition(b" ")
        if scheme.lower() == b"bearer" and self.verify(given.strip().decode("latin-1")):
            return await self.app(scope, receive, send)
        body = b'{"error":"unauthorized"}'
        await send({"type": "http.response.start", "status": 401, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"www-authenticate", b"Bearer")]})
        await send({"type": "http.response.body", "body": body})


def make_http_server(app: FastMCP, host: str, port: int, token: str | None, oauth: bool = False, verify=None) -> uvicorn.Server:
    """With ``oauth`` the app itself authenticates (OAuth tokens, plus the static token if one is set),
    and its discovery, authorize and token endpoints must stay reachable, so no blanket wrapper is added."""
    if not token and not verify and not oauth and not is_loopback(host):
        raise ValueError("refusing to listen on a non-loopback address without a token or OAuth")
    asgi = app.streamable_http_app()
    if (token or verify) and not oauth:
        asgi = BearerAuth(asgi, token, verify)
    return uvicorn.Server(uvicorn.Config(asgi, host=host, port=port, log_level="warning"))


def run_stdio(app: FastMCP, hub: Hub, reloader=None) -> None:
    async def main():
        if reloader:
            reloader.start()
        try:
            await app.run_stdio_async()
        finally:
            if reloader:
                await reloader.stop()
            await hub.stop()
    asyncio.run(main())


def run_http(app: FastMCP, hub: Hub, host: str, port: int, token: str | None, oauth: bool = False, reloader=None, verify=None) -> None:
    server = make_http_server(app, host, port, token, oauth, verify)

    async def main():
        if reloader:
            reloader.start()
        try:
            await server.serve()
        finally:
            if reloader:
                await reloader.stop()
            await hub.stop()
    asyncio.run(main())


def run_service(hub: Hub, public: uvicorn.Server | None, admin, reloader=None, restarter=None) -> None:
    """The long-running service: the local admin UI always, the public gateway listener only when remote access is set up.
    If either listener stops, the other one is stopped too, so a half-running service is never left behind."""
    if restarter:
        def stop_all():
            if public:
                public.should_exit = True
            admin.stop()
        restarter.attach(stop_all)

    async def main():
        if reloader:
            reloader.start()
        servers = [t for t in (public.serve() if public else None, admin.serve()) if t is not None]
        tasks = [asyncio.create_task(c) for c in servers]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                t.result()   # surface a crash
        finally:
            if public:
                public.should_exit = True
            admin.stop()
            await asyncio.gather(*tasks, return_exceptions=True)
            if reloader:
                await reloader.stop()
            await hub.stop()
    asyncio.run(main())
    if restarter and restarter.requested:
        raise SystemExit(restarter.EXIT_CODE)   # the service manager starts us again with the saved settings
