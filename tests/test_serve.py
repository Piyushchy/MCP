import asyncio

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mcpgate import serve, server
from mcpgate.config import Settings

TOKEN = "t" * 32


def test_loopback_detection():
    assert serve.is_loopback("127.0.0.1") and serve.is_loopback("localhost") and serve.is_loopback("::1")
    assert not serve.is_loopback("0.0.0.0") and not serve.is_loopback("192.168.1.5") and not serve.is_loopback("example.com")


def test_refuses_open_remote_listener_and_short_tokens():
    app, _ = server.build(Settings())
    with pytest.raises(ValueError, match="non-loopback"):
        serve.make_http_server(app, "0.0.0.0", 0, None)
    with pytest.raises(ValueError, match="at least"):
        serve.make_http_server(app, "127.0.0.1", 0, "short")
    serve.make_http_server(app, "127.0.0.1", 0, None)  # loopback without token is allowed


class _Both:
    """Enter the http client and the MCP transport together."""

    def __init__(self, client, transport):
        self.client, self.transport = client, transport

    async def __aenter__(self):
        await self.client.__aenter__()
        return await self.transport.__aenter__()

    async def __aexit__(self, *exc):
        try:
            return await self.transport.__aexit__(*exc)
        finally:
            await self.client.__aexit__(*exc)


async def run_server(app, token):
    srv = serve.make_http_server(app, "127.0.0.1", 0, token)
    task = asyncio.create_task(srv.serve())
    for _ in range(100):
        if srv.started:
            break
        await asyncio.sleep(0.05)
    port = srv.servers[0].sockets[0].getsockname()[1]
    return srv, task, f"http://127.0.0.1:{port}/mcp"


async def test_http_needs_the_token(demo_cfg):
    s = Settings()
    s.backends["demo"] = demo_cfg()
    app, hub = server.build(s)
    srv, task, url = await run_server(app, TOKEN)

    def authed():
        client = httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"})
        return _Both(client, streamable_http_client(url, http_client=client))

    try:
        async with httpx.AsyncClient() as h:
            for headers in ({}, {"Authorization": "Bearer wrong" + "x" * 30}, {"Authorization": "Basic " + TOKEN}):
                r = await h.post(url, headers=headers, json={})
                assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
        async with authed() as (r, w, _):
            async with ClientSession(r, w) as c:
                await c.initialize()
                names = {t.name for t in (await c.list_tools()).tools}
                assert "call_tool" in names
                res = await c.call_tool("call_tool", {"name": "demo.add", "arguments": {"a": 20, "b": 22}})
                assert res.content[0].text == "42"
        # the backend survives a client leaving (the hub is not tied to one session)
        async with authed() as (r, w, _):
            async with ClientSession(r, w) as c:
                await c.initialize()
                assert hub.backends["demo"].connected
    finally:
        srv.should_exit = True
        await asyncio.wait_for(task, 20)
        await hub.stop()


async def _status(url, host, token):
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}
    async with httpx.AsyncClient() as h:
        r = await h.post(url, json=init, headers={
            "Host": host, "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream", "Content-Type": "application/json"})
        return r.status_code


async def test_allow_host_accepts_a_tunnel_host_header_and_still_rejects_others():
    sec = serve.transport_security(["box.tail1234.ts.net"])
    app, hub = server.build(Settings(), transport_security=sec)
    srv, task, url = await run_server(app, TOKEN)
    try:
        assert await _status(url, "box.tail1234.ts.net", TOKEN) == 200
        assert await _status(url, "evil.example.com", TOKEN) in (400, 421)
    finally:
        srv.should_exit = True
        await asyncio.wait_for(task, 20)
        await hub.stop()


async def test_default_server_rejects_a_foreign_host_header():
    app, hub = server.build(Settings())
    srv, task, url = await run_server(app, TOKEN)
    try:
        assert await _status(url, "box.tail1234.ts.net", TOKEN) in (400, 421)  # the reason --allow-host exists
    finally:
        srv.should_exit = True
        await asyncio.wait_for(task, 20)
        await hub.stop()
