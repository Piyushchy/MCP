import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session as connect

from mcpgate import server
from mcpgate.approvals import MAX_PENDING, Approvals, mask
from mcpgate.config import Backend, Settings
from mcpgate.hub import GatewayError, Hub

DEMO = str(Path(__file__).parent / "fixtures" / "demo_server.py")
CANARY = "canary-s3cr3t-7f3a91c2"


class Clock:
    now = 1000.0

    def __call__(self):
        return self.now


@asynccontextmanager
async def rig(tmp_path, wait=0.05, confirm=("echo",), deny=()):
    audit = tmp_path / "audit.jsonl"
    s = Settings(audit_log=str(audit), backends={"demo": Backend(name="demo", transport="stdio", command=sys.executable, args=[DEMO],
                                                                  confirm=list(confirm), deny=list(deny))})
    hub = Hub(s)
    clock = Clock()
    hub.approvals = Approvals(clock=clock, wall=clock, wait=wait, audit=lambda **f: hub.audit.log(**f))
    try:
        yield hub, hub.approvals, clock, audit
    finally:
        await hub.stop()


def events(audit, name=None):
    rows = [json.loads(x) for x in audit.read_text().splitlines()]
    return [r for r in rows if "event" in r and (name is None or r["event"] == name)]


def text(blocks):
    return "\n".join(b.text for b in blocks if b.type == "text")


async def call(hub, args=None, tool="demo.echo"):
    return text(await hub.call(tool, args or {"text": "hello"}))


async def test_model_is_told_to_wait_and_gets_nothing_to_approve_itself(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError) as e:
            await call(hub)
        msg = str(e.value)
        pend = q.pending()
        assert len(pend) == 1 and pend[0].tool == "demo.echo"
        assert "waiting for the owner's approval" in msg and "retry the identical call" in msg
        assert pend[0].id not in msg and "confirm" not in msg.lower() and pend[0].key not in msg
        with pytest.raises(GatewayError):
            await hub.call("demo.echo", {"text": "hello"}, confirm="anything-the-model-guesses")
        assert len(q.pending()) == 1                       # a guessed code does nothing and no second request is created


async def test_approve_runs_the_call_exactly_once(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub)
        q.approve(q.pending()[0].id)
        assert "hello" in await call(hub)                  # the retry runs
        with pytest.raises(GatewayError):                  # and it was single use: the same call asks again
            await call(hub)
        assert len(q.pending()) == 1


async def test_a_waiting_call_returns_the_result_as_soon_as_the_owner_approves(tmp_path):
    async with rig(tmp_path, wait=5) as (hub, q, clock, audit):
        task = asyncio.create_task(call(hub))
        for _ in range(100):
            if q.pending():
                break
            await asyncio.sleep(0.01)
        q.approve(q.pending()[0].id)
        assert "hello" in await asyncio.wait_for(task, 3)


async def test_changed_arguments_need_a_new_approval(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub, {"text": "one"})
        q.approve(q.pending()[0].id)
        with pytest.raises(GatewayError):
            await call(hub, {"text": "two"})               # approved "one", asked for "two"
        assert [json.loads(q.view(r)["args"])["text"] for r in q.pending()] == ["two"]
        assert "one" in await call(hub, {"text": "one"})


async def test_deny_makes_retries_fail_clearly_then_asks_again_later(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub)
        q.deny(q.pending()[0].id)
        for _ in range(2):
            with pytest.raises(GatewayError, match="owner denied this call"):
                await call(hub)
        assert q.pending() == []                           # a denied call does not pile up new requests
        clock.now += 301
        with pytest.raises(GatewayError, match="waiting"):
            await call(hub)                                # after a while it may be asked again
        assert len(q.pending()) == 1


async def test_unanswered_requests_expire_and_are_reported(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub)
        clock.now += 301
        with pytest.raises(GatewayError, match="expired without an answer"):
            await call(hub)
        with pytest.raises(GatewayError, match="waiting"):
            await call(hub)                                # and a fresh request is made on the next call
        assert [e["was"] for e in events(audit, "approval_expired")] == ["pending"]


async def test_an_approval_nobody_used_expires_too(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub)
        q.approve(q.pending()[0].id)
        clock.now += 301
        with pytest.raises(GatewayError, match="expired"):
            await call(hub)
        assert events(audit, "approval_expired")[0]["was"] == "approved"


async def test_expired_entries_nobody_retries_are_forgotten(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub)
        clock.now += 301
        q.pending()
        assert len(q.by_key) == 1
        clock.now += 301
        q.pending()
        assert q.by_key == {}


async def test_approve_for_a_while_covers_only_that_exact_call(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub)
        q.approve(q.pending()[0].id, minutes=15)
        for _ in range(3):
            assert "hello" in await call(hub)
        with pytest.raises(GatewayError):
            await call(hub, {"text": "other"})
        clock.now += 15 * 60 + 1
        with pytest.raises(GatewayError, match="waiting"):
            await call(hub)                                # the grant ran out


@pytest.mark.parametrize("minutes", [-1, 61, "5", 1.5, True, None])
async def test_bad_grant_minutes_rejected(tmp_path, minutes):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub)
        with pytest.raises(ValueError):
            q.approve(q.pending()[0].id, minutes)
        assert len(q.pending()) == 1                       # still waiting, unchanged


async def test_deciding_twice_is_refused(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub)
        rid = q.pending()[0].id
        q.deny(rid)
        with pytest.raises(ValueError, match="already denied"):
            q.approve(rid)
        with pytest.raises(KeyError):
            q.approve("0" * 16)


async def test_destructive_tools_and_patterns_both_go_through_the_queue(tmp_path):
    async with rig(tmp_path, confirm=()) as (hub, q, clock, audit):
        with pytest.raises(GatewayError, match="waiting"):
            await hub.call("demo.wipe", {"target": "x"})   # destructive hint, no pattern
        assert q.pending()[0].tool == "demo.wipe"
        assert "hello" in text(await hub.call("demo.echo", {"text": "hello"}))   # ordinary tools are untouched


async def test_blocked_tools_never_reach_the_queue(tmp_path):
    async with rig(tmp_path, deny=("echo",)) as (hub, q, clock, audit):
        with pytest.raises(GatewayError, match="blocked"):
            await call(hub)
        assert q.pending() == []


async def test_audit_records_every_step_without_secrets(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        args = {"text": "x", "api_token": CANARY}
        with pytest.raises(GatewayError):
            await call(hub, args)
        q.approve(q.pending()[0].id)
        await call(hub, args)
        with pytest.raises(GatewayError):
            await call(hub, {"text": "y"})
        q.deny(q.pending()[0].id)
        clock.now += 400
        q.pending()
        names = [e["event"] for e in events(audit)]
        assert names == ["approval_requested", "approval_approved", "approval_requested", "approval_denied"]
        assert CANARY not in audit.read_text()


async def test_the_owner_sees_exact_arguments_with_secret_keys_masked(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        args = {"text": "x" * 500, "nested": {"password": CANARY, "keep": [1, {"authorization": CANARY, "n": 2}]}, "api_key": CANARY}
        with pytest.raises(GatewayError):
            await call(hub, args)
        v = q.view(q.pending()[0])
        shown = json.loads(v["args"])
        assert shown["text"] == "x" * 500                       # not shortened: it is what will run
        assert shown["api_key"] == "***" and shown["nested"]["password"] == "***" and shown["nested"]["keep"][1]["authorization"] == "***"
        assert shown["nested"]["keep"][1]["n"] == 2 and CANARY not in v["args"] and v["tool"] == "demo.echo"
        assert mask({"Token": 1}) == {"Token": "***"}


async def test_huge_arguments_cannot_be_approved_or_flood_the_queue(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError, match="too large"):
            await call(hub, {"text": "x" * 200_000})
        assert q.pending() == []
        for i in range(MAX_PENDING):
            with pytest.raises(GatewayError, match="waiting"):
                await call(hub, {"text": f"n{i}"})
        with pytest.raises(GatewayError, match="too many approval requests"):
            await call(hub, {"text": "one more"})
        assert len(q.pending()) == MAX_PENDING


async def test_display_scrubs_stored_secret_values(tmp_path):
    from mcpgate.secretstore import SecretStore
    store = SecretStore(tmp_path / "s.json")
    store.set("TOK", CANARY)
    async with rig(tmp_path) as (hub, q, clock, audit):
        q.scrub = store.scrub
        with pytest.raises(GatewayError):
            await call(hub, {"text": f"please use {CANARY} here"})
        assert CANARY not in q.view(q.pending()[0])["args"]


async def test_nothing_the_model_can_see_contains_anything_that_approves(tmp_path):
    """Through the real MCP surface: every tool response and error, collected, never holds a request id or code."""
    s = Settings(audit_log=str(tmp_path / "a.jsonl"), backends={"demo": Backend(name="demo", transport="stdio", command=sys.executable,
                                                                                  args=[DEMO], confirm=["echo"])})
    hub = Hub(s)
    hub.approvals = Approvals(wait=0.05)
    app, hub = server.build(s, hub=hub)
    seen = []
    try:
        async with connect(app._mcp_server) as c:
            assert "owner to approve it in their admin page" in (app._mcp_server.instructions or "")
            assert "confirm code" not in (app._mcp_server.instructions or "")
            seen.append(text((await c.call_tool("call_tool", {"name": "demo.echo", "arguments": {"text": "a"}})).content))
            seen.append(text((await c.call_tool("call_tool", {"name": "demo.echo", "arguments": {"text": "a"}, "confirm": "guess"})).content))
            seen.append(text((await c.call_tool("search_tools", {"query": "echo"})).content))
            seen.append(text((await c.call_tool("describe_tool", {"name": "demo.echo"})).content))
            seen.append(text((await c.call_tool("list_backends", {})).content))
        rid = hub.approvals.pending()[0].id
        key = hub.approvals.pending()[0].key
        blob = "\n".join(seen)
        assert rid not in blob and key not in blob and "confirm=" not in blob and "confirm code" not in blob
        assert "waiting for the owner" in blob
    finally:
        await hub.stop()


async def test_without_the_service_the_old_code_flow_still_works(tmp_path):
    s = Settings(backends={"demo": Backend(name="demo", transport="stdio", command=sys.executable, args=[DEMO], confirm=["echo"])})
    hub = Hub(s)
    try:
        assert hub.approvals is None
        with pytest.raises(GatewayError) as e:
            await hub.call("demo.echo", {"text": "hi"})
        assert 'confirm="' in str(e.value)
    finally:
        await hub.stop()


async def test_pending_requests_are_lost_on_restart_never_auto_approved(tmp_path):
    async with rig(tmp_path) as (hub, q, clock, audit):
        with pytest.raises(GatewayError):
            await call(hub)
    (tmp_path / "again").mkdir()
    async with rig(tmp_path / "again") as (hub2, q2, clock2, audit2):
        assert q2.pending() == []
        with pytest.raises(GatewayError, match="waiting"):
            await call(hub2)                                # asks again, did not run
