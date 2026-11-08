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

    def __init__(self, app, token: str):
        if len(token) < MIN_TOKEN:
            raise ValueError(f"token must be at least {MIN_TOKEN} characters (try: mcpgate token)")
        self.app, self.token = app, token.encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":  # lifespan etc. pass straight through
            return await self.app(scope, receive, send)
        auth = dict(scope["headers"]).get(b"authorization", b"")
        scheme, _, given = auth.partition(b" ")
        if scheme.lower() == b"bearer" and hmac.compare_digest(given.strip(), self.token):
            return await self.app(scope, receive, send)
        body = b'{"error":"unauthorized"}'
        await send({"type": "http.response.start", "status": 401, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"www-authenticate", b"Bearer")]})
        await send({"type": "http.response.body", "body": body})


def make_http_server(app: FastMCP, host: str, port: int, token: str | None, oauth: bool = False) -> uvicorn.Server:
    """With ``oauth`` the app itself authenticates (OAuth tokens, plus the static token if one is set),
    and its discovery, authorize and token endpoints must stay reachable, so no blanket wrapper is added."""
    if not token and not oauth and not is_loopback(host):
        raise ValueError("refusing to listen on a non-loopback address without a token or OAuth")
    asgi = app.streamable_http_app()
    if token and not oauth:
        asgi = BearerAuth(asgi, token)
    return uvicorn.Server(uvicorn.Config(asgi, host=host, port=port, log_level="warning"))


def run_stdio(app: FastMCP, hub: Hub) -> None:
    async def main():
        try:
            await app.run_stdio_async()
        finally:
            await hub.stop()
    asyncio.run(main())


def run_http(app: FastMCP, hub: Hub, host: str, port: int, token: str | None, oauth: bool = False) -> None:
    server = make_http_server(app, host, port, token, oauth)

    async def main():
        try:
            await server.serve()
        finally:
            await hub.stop()
    asyncio.run(main())
