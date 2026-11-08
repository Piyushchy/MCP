import re
import socket
import threading

import pytest
from starlette.testclient import TestClient

from mcpgate.admin import app as admin
from mcpgate.admin.app import ADMIN_HOST, AdminError, AdminServer, Spec, make_app

PORT = 8767
H = {"host": f"127.0.0.1:{PORT}"}


async def _ok(request):
    return admin.JSONResponse({"ok": True})


@pytest.fixture
def client():
    extra = [Spec("/api/thing", ("GET", "POST"), _ok, session=True, csrf=True)]
    return TestClient(make_app(PORT, extra), base_url=f"http://127.0.0.1:{PORT}")


def test_shell_and_health(client):
    assert client.get("/", headers=H).status_code == 200
    assert client.get("/api/health", headers=H).json() == {"ok": True}
    assert "javascript" in client.get("/static/app.js", headers=H).headers["content-type"]


def test_security_headers_on_every_response_even_errors(client):
    for r in (client.get("/", headers=H), client.get("/nope", headers=H), client.get("/", headers={"host": "evil.example"})):
        assert r.headers["x-frame-options"] == "DENY" and r.headers["referrer-policy"] == "no-referrer"
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
        csp = r.headers["content-security-policy"]
        assert "default-src 'none'" in csp and "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
        assert not re.search(r"https?://", csp)


@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1", f"127.0.0.1:{PORT + 1}", f"evil.example:{PORT}", "", f"[::1]:{PORT}"])
def test_wrong_host_rejected(client, host):
    assert client.get("/api/health", headers={"host": host}).status_code == 400


@pytest.mark.parametrize("name", ["X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "CF-Connecting-IP",
                                  "Tailscale-User-Login", "Via", "X-Real-IP"])
def test_proxy_headers_rejected(client, name):
    assert client.get("/api/health", headers={**H, name: "x"}).status_code == 400


def test_localhost_name_is_accepted(client):
    assert client.get("/api/health", headers={"host": f"localhost:{PORT}"}).status_code == 200


def test_state_changing_needs_matching_origin(client):
    assert client.post("/api/thing", headers=H).status_code == 403
    assert client.post("/api/thing", headers={**H, "origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/thing", headers={**H, "origin": f"http://localhost:{PORT}"}).status_code == 403   # must match Host exactly
    assert client.post("/api/thing", headers={**H, "origin": f"http://127.0.0.1:{PORT}"}).status_code == 200


def test_unknown_paths_and_methods_are_404(client):
    assert client.get("/admin", headers=H).status_code == 404
    assert client.delete("/api/health", headers={**H, "origin": f"http://127.0.0.1:{PORT}"}).status_code == 404


def test_every_state_changing_route_declares_csrf():
    for s in admin.ROUTES:
        if s.state_changing:
            assert s.csrf and s.session, s.path


def test_page_has_no_inline_script_or_outside_resources():
    page = (admin.STATIC / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", page) and not re.search(r"\son\w+\s*=", page)
    assert not re.search(r"(src|href)=[\"']https?:", page)
    assert "innerHTML" not in (admin.STATIC / "app.js").read_text()


def test_binds_loopback_only_and_never_falls_back():
    assert ADMIN_HOST == "127.0.0.1"
    busy = socket.socket()
    busy.bind((ADMIN_HOST, 0))
    port = busy.getsockname()[1]
    try:
        with pytest.raises(AdminError, match="will not start elsewhere"):
            AdminServer(port)
    finally:
        busy.close()
    s = AdminServer(0)
    try:
        assert s.sock.getsockname()[0] == "127.0.0.1"
    finally:
        s.sock.close()


async def test_real_server_serves_on_loopback():
    import asyncio
    import httpx
    s = AdminServer(0)
    port = s.sock.getsockname()[1]
    s.server.config.app = make_app(port)
    task = asyncio.create_task(s.serve())
    try:
        async with httpx.AsyncClient() as c:
            for _ in range(50):
                try:
                    r = await c.get(f"http://127.0.0.1:{port}/api/health")
                    break
                except httpx.ConnectError:
                    await asyncio.sleep(0.1)
            assert r.status_code == 200 and r.json() == {"ok": True}
            assert (await c.get(f"http://127.0.0.1:{port}/", headers={"host": f"evil:{port}"})).status_code == 400
    finally:
        s.stop()
        await task
