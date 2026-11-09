import asyncio
import json

import httpx
import pytest

from mcpgate.approvals import Approvals
from mcpgate.hub import GatewayError
from tests.admin_helpers import HOST, demo, rig

CANARY = "canary-s3cr3t-7f3a91c2"


def serviced(hub, wait=0.05):
    hub.approvals = Approvals(wait=wait, audit=lambda **f: hub.audit.log(**f), scrub=hub._scrub)
    return hub.approvals


async def ask(hub, args=None):
    try:
        await hub.call("demo.echo", args or {"text": "hello"})
    except GatewayError:
        pass


async def test_requires_login_and_csrf(tmp_path):
    async with rig(tmp_path, {"demo": demo(confirm=["echo"])}) as r:
        q = serviced(r.hub)
        await ask(r.hub)
        rid = q.pending()[0].id
        for action in ["approve", "deny"]:
            assert (await r.post(f"/api/approvals/{rid}/{action}", csrf=False)).status_code == 403
        assert q.pending() and q.pending()[0].state == "pending"
        r.c.cookies.clear()
        assert (await r.get("/api/approvals")).status_code == 401
        assert (await r.c.post(f"/api/approvals/{rid}/approve", headers={"host": HOST, "origin": f"http://{HOST}", "content-type": "application/json"},
                               content="{}")).status_code == 401


async def test_a_forged_approval_from_a_web_page_is_refused(tmp_path):
    async with rig(tmp_path, {"demo": demo(confirm=["echo"])}) as r:
        q = serviced(r.hub)
        await ask(r.hub)
        rid = q.pending()[0].id
        # the browser would send the cookie; the page cannot set a matching Origin or read the CSRF token
        for headers in [{"origin": "https://evil.example"}, {"origin": "null"}, {"origin": ""}]:
            h = {**r.headers(), **headers}
            resp = await r.c.post(f"/api/approvals/{rid}/approve", headers=h, content="{}")
            assert resp.status_code == 403
        h = {**r.headers(), "x-csrf-token": "forged"}
        assert (await r.c.post(f"/api/approvals/{rid}/approve", headers=h, content="{}")).status_code == 403
        assert q.pending()[0].state == "pending"


async def test_list_shows_exact_masked_arguments_and_a_counter(tmp_path):
    async with rig(tmp_path, {"demo": demo(confirm=["echo"])}, secrets={"TOK": CANARY}) as r:
        q = serviced(r.hub)
        assert (await r.get("/api/approvals")).json() == {"pending": [], "count": 0, "recent": [], "available": True}
        await ask(r.hub, {"text": "x" * 300, "api_key": CANARY, "note": f"via {CANARY}"})
        await ask(r.hub, {"text": "second"})
        body = (await r.get("/api/approvals")).json()
        assert body["count"] == 2 and CANARY not in json.dumps(body)
        first = body["pending"][0]
        args = json.loads(first["args"])
        assert args["text"] == "x" * 300 and args["api_key"] == "***" and first["tool"] == "demo.echo" and first["expires_in"] > 0


async def test_approve_deny_and_history_through_the_api(tmp_path):
    async with rig(tmp_path, {"demo": demo(confirm=["echo"])}) as r:
        q = serviced(r.hub)
        await ask(r.hub, {"text": "one"})
        await ask(r.hub, {"text": "two"})
        one, two = [p["id"] for p in (await r.get("/api/approvals")).json()["pending"]]
        assert (await r.post(f"/api/approvals/{one}/approve")).json() == {"id": one, "state": "approved", "minutes": 0}
        assert (await r.post(f"/api/approvals/{two}/deny")).json() == {"id": two, "state": "denied"}
        assert (await r.get("/api/approvals")).json()["count"] == 0
        assert [h["state"] for h in (await r.get("/api/approvals")).json()["recent"]] == ["denied", "approved"]
        assert "one" in (await r.hub.call("demo.echo", {"text": "one"}))[0].text            # the approved call runs
        with pytest.raises(GatewayError, match="denied"):
            await r.hub.call("demo.echo", {"text": "two"})


async def test_approve_for_minutes_and_validation(tmp_path):
    async with rig(tmp_path, {"demo": demo(confirm=["echo"])}) as r:
        q = serviced(r.hub)
        await ask(r.hub)
        rid = q.pending()[0].id
        for bad in [{"minutes": 500}, {"minutes": -1}, {"minutes": "5"}, {"minutes": True}]:
            assert (await r.post(f"/api/approvals/{rid}/approve", bad)).status_code == 400
        assert (await r.post(f"/api/approvals/{rid}/approve", {"minutes": 15})).json()["minutes"] == 15
        for _ in range(2):
            assert "hello" in (await r.hub.call("demo.echo", {"text": "hello"}))[0].text


async def test_unknown_malformed_and_already_decided_ids(tmp_path):
    async with rig(tmp_path, {"demo": demo(confirm=["echo"])}) as r:
        q = serviced(r.hub)
        await ask(r.hub)
        rid = q.pending()[0].id
        for bad in ["0" * 16, "xyz", "../x", "A" * 16]:
            assert (await r.post(f"/api/approvals/{bad}/approve")).status_code == 404
        assert (await r.post(f"/api/approvals/{rid}/deny")).status_code == 200
        resp = await r.post(f"/api/approvals/{rid}/approve")
        assert resp.status_code == 409 and "already denied" in resp.json()["error"]


async def test_not_available_without_the_service(tmp_path):
    async with rig(tmp_path) as r:
        assert (await r.get("/api/approvals")).json()["available"] is False
        assert (await r.post("/api/approvals/" + "0" * 16 + "/approve")).status_code == 409


async def test_the_page_updates_by_polling_and_a_decision_wakes_the_waiting_call(tmp_path):
    async with rig(tmp_path, {"demo": demo(confirm=["echo"])}) as r:
        q = serviced(r.hub, wait=5)
        task = asyncio.create_task(r.hub.call("demo.echo", {"text": "live"}))
        for _ in range(100):
            if (await r.get("/api/approvals")).json()["count"]:
                break
            await asyncio.sleep(0.02)
        rid = (await r.get("/api/approvals")).json()["pending"][0]["id"]
        assert (await r.post(f"/api/approvals/{rid}/approve")).status_code == 200
        assert "live" in (await asyncio.wait_for(task, 3))[0].text
        assert (await r.get("/api/approvals")).json()["count"] == 0


async def test_decisions_are_audited_as_admin_actions_free_of_secrets(tmp_path):
    async with rig(tmp_path, {"demo": demo(confirm=["echo"])}) as r:
        q = serviced(r.hub)
        await ask(r.hub, {"text": "x", "password": CANARY})
        await r.post(f"/api/approvals/{q.pending()[0].id}/approve")
        rows = [json.loads(x) for x in r.audit_text().splitlines()]
        assert [x["event"] for x in rows if x.get("event", "").startswith("approval_")] == ["approval_requested", "approval_approved"]
        assert CANARY not in r.audit_text()
