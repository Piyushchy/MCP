import asyncio
import socket

import pytest

from mcpgate.admin import friendly
from mcpgate.config import Backend
from tests.admin_helpers import rig

CANARY = "canary-s3cr3t-7f3a91c2"


@pytest.mark.parametrize("text,needle", [
    ("[Errno 2] No such file or directory: 'uvx'", "not found on this computer"),
    ("sh: foo: command not found", "not found on this computer"),
    ("PermissionError: [Errno 13] Permission denied: '/x/y'", "permission denied"),
    ("Client error '401 Unauthorized' for url 'https://x/mcp'", "did not accept the token"),
    ("HTTP 403 Forbidden", "refused access"),
    ("Client error '404 Not Found' for url 'https://x/mcp'", "Nothing was found at that address"),
    ("429 Too Many Requests", "too many requests"),
    ("Server error '502 Bad Gateway'", "problem of its own"),
    ("[Errno -2] Name or service not known", "host name could not be found"),
    ("All connection attempts failed", "Nothing answered"),
    ("[SSL: CERTIFICATE_VERIFY_FAILED]", "certificate"),
    ("ReadTimeout", "did not answer in time"),
    ("Connection closed", "stopped straight away"),
    ("McpError: Session terminated", "Nothing was found at that address"),
])
def test_known_failures_get_plain_words_and_a_next_step(text, needle):
    plain, hint = friendly.explain(text, "uvx")
    assert needle.lower() in plain.lower() and hint


def test_unknown_failures_say_nothing_rather_than_guess():
    assert friendly.explain("something odd happened") == ("", "")


def test_exception_groups_are_unwrapped():
    g = ExceptionGroup("unhandled errors in a TaskGroup", [ExceptionGroup("inner", [FileNotFoundError(2, "No such file or directory", "npx")])])
    assert "“npx” was not found" in friendly.explain(g, "npx")[0]


async def tiny_server(status_line: bytes):
    async def handle(reader, writer):
        await reader.read(2000)
        writer.write(status_line + b"\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


def closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def probe(r, name):
    resp = await r.post(f"/api/backends/{name}/test")
    assert resp.status_code == 200
    return resp.json()


async def test_a_missing_program_is_explained_by_the_test_button(tmp_path):
    b = Backend(name="nope", transport="stdio", command="definitely-not-a-real-program-xyz", start_timeout=10)
    async with rig(tmp_path, {"nope": b}) as r:
        t = await probe(r, "nope")
        assert t["ok"] is False and "not found on this computer" in t["error"] and t["hint"] and "definitely-not-a-real-program-xyz" in t["error"]


@pytest.mark.parametrize("line,needle", [(b"HTTP/1.1 401 Unauthorized", "did not accept the token"), (b"HTTP/1.1 403 Forbidden", "refused access"),
                                         (b"HTTP/1.1 404 Not Found", "Nothing was found at that address")])
async def test_http_errors_from_a_real_server_are_explained(tmp_path, line, needle):
    srv, port = await tiny_server(line)
    try:
        b = Backend(name="web", transport="http", url=f"http://127.0.0.1:{port}/mcp", start_timeout=10)
        async with rig(tmp_path, {"web": b}) as r:
            t = await probe(r, "web")
            assert t["ok"] is False and needle in t["error"] and t["hint"], t
    finally:
        srv.close()


async def test_a_refused_connection_is_explained_and_the_row_carries_the_hint(tmp_path):
    b = Backend(name="web", transport="http", url=f"http://127.0.0.1:{closed_port()}/mcp", start_timeout=10)
    async with rig(tmp_path, {"web": b}) as r:
        t = await probe(r, "web")
        assert t["ok"] is False and "Nothing answered" in t["error"] and t["hint"]
        row = (await r.get("/api/backends")).json()["backends"][0]
        assert "error_hint" in row


async def test_errors_never_show_a_stored_secret(tmp_path):
    b = Backend(name="web", transport="http", url=f"http://127.0.0.1:{closed_port()}/mcp", headers={"Authorization": "Bearer ${TOK}"}, start_timeout=10)
    async with rig(tmp_path, {"web": b}, secrets={"TOK": CANARY}) as r:
        t = await probe(r, "web")
        assert CANARY not in str(t)
