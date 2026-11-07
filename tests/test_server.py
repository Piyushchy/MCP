import json
from contextlib import asynccontextmanager

import pytest
from mcp.shared.memory import create_connected_server_and_client_session as connect

from mcpgate import server
from mcpgate.config import Settings


def settings(demo_cfg, **kw):
    s = Settings(cache_ttl=kw.pop("cache_ttl", 60), max_result_chars=kw.pop("max_result_chars", 20000),
                 audit_log=kw.pop("audit_log", ""))
    s.backends["demo"] = demo_cfg(**kw)
    return s


@asynccontextmanager
async def opened(demo_cfg):
    """A client connected to a gateway with the demo backend (opened and closed in one task)."""
    app, hub = server.build(settings(demo_cfg, deny=["die"], confirm=["delete_*", "create_*"]))
    try:
        async with connect(app._mcp_server) as c:
            yield c
    finally:
        await hub.stop()


def text(res):
    return "\n".join(b.text for b in res.content if b.type == "text")


async def test_only_meta_tools_are_exposed(demo_cfg):
    async with opened(demo_cfg) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert names == {"search_tools", "describe_tool", "call_tool", "list_backends", "read_result"}


async def test_search_shows_names_and_arguments(demo_cfg):
    async with opened(demo_cfg) as client:
        out = text(await client.call_tool("search_tools", {"query": "add numbers"}))
        assert "demo.add" in out and "(a*, b*)" in out
        out = text(await client.call_tool("search_tools", {"query": "note"}))
        assert "demo.create_note" in out and "[needs approval]" in out
        assert "No tools match" in text(await client.call_tool("search_tools", {"query": "zzzzqq"}))


async def test_denied_tools_are_invisible_and_uncallable(demo_cfg):
    async with opened(demo_cfg) as client:
        assert "demo.die" not in text(await client.call_tool("search_tools", {"query": "", "limit": 30}))
        res = await client.call_tool("call_tool", {"name": "demo.die"})
        assert res.isError and "blocked" in text(res)
        res = await client.call_tool("describe_tool", {"name": "demo.die"})
        assert res.isError


async def test_describe_gives_the_schema(demo_cfg):
    async with opened(demo_cfg) as client:
        d = json.loads(text(await client.call_tool("describe_tool", {"name": "demo.add"})))
        assert d["arguments"]["required"] == ["a", "b"] and d["read_only"] and not d["needs_approval"]


async def test_call_routes_to_the_backend(demo_cfg):
    async with opened(demo_cfg) as client:
        assert text(await client.call_tool("call_tool", {"name": "demo.add", "arguments": {"a": 4, "b": 5}})) == "9"
        assert text(await client.call_tool("call_tool", {"name": "demo.echo", "arguments": {"text": "hi"}})) == "hi"


async def test_bad_names_and_unknown_backends_give_helpful_errors(demo_cfg):
    async with opened(demo_cfg) as client:
        r = await client.call_tool("call_tool", {"name": "nodot"})
        assert r.isError and "backend.tool" in text(r)
        r = await client.call_tool("call_tool", {"name": "nope.x"})
        assert r.isError and "No backend named" in text(r) and "demo" in text(r)
        r = await client.call_tool("call_tool", {"name": "demo.missing"})
        assert r.isError and "no tool" in text(r)


async def test_tool_errors_are_errors(demo_cfg):
    async with opened(demo_cfg) as client:
        r = await client.call_tool("call_tool", {"name": "demo.explode"})
        assert r.isError and "boom" in text(r)


async def test_read_only_results_are_cached(demo_cfg):
    async with opened(demo_cfg) as client:
        a = text(await client.call_tool("call_tool", {"name": "demo.counter"}))
        b = text(await client.call_tool("call_tool", {"name": "demo.counter"}))
        assert a == b == "1"


async def test_cache_can_be_turned_off(demo_cfg):
    app, hub = server.build(settings(demo_cfg, cache_ttl=0))
    async with connect(app._mcp_server) as c:
        a = text(await c.call_tool("call_tool", {"name": "demo.counter"}))
        b = text(await c.call_tool("call_tool", {"name": "demo.counter"}))
    await hub.stop()
    assert (a, b) == ("1", "2")


async def test_confirmation_flow(demo_cfg):
    async with opened(demo_cfg) as client:
        args = {"name": "demo.create_note", "arguments": {"title": "t"}}
        r = await client.call_tool("call_tool", args)
        assert r.isError and "approval" in text(r)
        token = text(r).split('confirm="')[1].split('"')[0]
        # a token does not work for different arguments
        bad = await client.call_tool("call_tool", {**args, "arguments": {"title": "other"}, "confirm": token})
        assert bad.isError and "not valid" in text(bad)
        # the right token works once...
        ok = await client.call_tool("call_tool", {**args, "confirm": token})
        assert not ok.isError and text(ok) == "created t"
        # ...and only once
        again = await client.call_tool("call_tool", {**args, "confirm": token})
        assert again.isError


async def test_destructive_hint_needs_approval_even_without_config(demo_cfg):
    async with opened(demo_cfg) as client:
        r = await client.call_tool("call_tool", {"name": "demo.wipe", "arguments": {"target": "x"}})
        assert r.isError and "approval" in text(r)


async def test_long_results_are_cut_and_can_be_paged(demo_cfg):
    app, hub = server.build(settings(demo_cfg, max_result_chars=500))
    async with connect(app._mcp_server) as c:
        out = text(await c.call_tool("call_tool", {"name": "demo.big", "arguments": {"n": 1200}}))
        assert out.startswith("x" * 500) and "Result cut" in out
        rid = out.split('result_id="')[1].split('"')[0]
        more = text(await c.call_tool("read_result", {"result_id": rid, "offset": 500, "length": 500}))
        assert more.startswith("x" * 500) and "continue with offset=1000" in more
        last = text(await c.call_tool("read_result", {"result_id": rid, "offset": 1000}))
        assert "end]" in last
        bad = await c.call_tool("read_result", {"result_id": "nope"})
        assert bad.isError
    await hub.stop()


async def test_unreachable_backend_does_not_break_search(demo_cfg):
    s = settings(demo_cfg)
    from mcpgate.config import Backend
    s.backends["ghost"] = Backend(name="ghost", command="/no/such/binary")
    app, hub = server.build(s)
    async with connect(app._mcp_server) as c:
        out = text(await c.call_tool("search_tools", {"query": "echo"}))
        assert "demo.echo" in out and "Unavailable: ghost" in out
        assert "ghost  stdio  error" in text(await c.call_tool("list_backends", {}))
    await hub.stop()


async def test_audit_log_records_calls_and_hides_secrets(demo_cfg, tmp_path):
    log = tmp_path / "audit.jsonl"
    app, hub = server.build(settings(demo_cfg, audit_log=str(log)))
    async with connect(app._mcp_server) as c:
        await c.call_tool("call_tool", {"name": "demo.echo", "arguments": {"text": "hello", "api_key": "SECRET123"}})
        await c.call_tool("call_tool", {"name": "demo.explode"})
    await hub.stop()
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r["status"] for r in rows] == ["ok", "tool_error"]
    assert rows[0]["args"]["api_key"] == "***" and "SECRET123" not in log.read_text()
    assert (log.stat().st_mode & 0o777) == 0o600
