import asyncio
import sys

import pytest

from mcpgate.backends import Backend, BackendError
from mcpgate.config import Backend as Cfg


async def test_starts_lazily_lists_and_calls(demo_cfg):
    b = Backend(demo_cfg())
    try:
        assert b.status() == "idle" and not b.connected
        tools = await b.tools()
        assert b.status() == "connected"
        by = {t.name: t for t in tools}
        assert {"echo", "add", "wipe", "create_note"} <= set(by)
        assert by["echo"].read_only and not by["create_note"].read_only
        assert by["wipe"].destructive and by["echo"].full == "demo.echo"
        res = await b.call("add", {"a": 2, "b": 3})
        assert not res.isError and res.content[0].text == "5"
    finally:
        await b.stop()
    assert b.status() == "idle"


async def test_tool_errors_come_back_as_error_results(demo_cfg):
    b = Backend(demo_cfg())
    try:
        res = await b.call("explode", {})
        assert res.isError and "boom" in res.content[0].text
    finally:
        await b.stop()


async def test_backend_gets_only_its_configured_env(demo_cfg, monkeypatch):
    monkeypatch.setenv("GATEWAY_ONLY", "should-not-leak")
    monkeypatch.setenv("TOKEN_X", "abc")
    b = Backend(demo_cfg(env={"DEMO_SECRET": "${TOKEN_X}"}))
    try:
        res = await b.call("whoami", {})
        assert res.content[0].text == "secret=abc leak=-"
    finally:
        await b.stop()


async def test_missing_env_var_is_a_clear_error(demo_cfg, monkeypatch):
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    b = Backend(demo_cfg(env={"DEMO_SECRET": "${NOT_SET_ANYWHERE}"}))
    with pytest.raises(BackendError, match="NOT_SET_ANYWHERE"):
        await b.tools()
    assert "NOT_SET_ANYWHERE" in b.status()


async def test_bad_command_is_reported_not_raised_raw():
    b = Backend(Cfg(name="ghost", command="/definitely/not/here"), start_timeout=5)
    with pytest.raises(BackendError, match="ghost"):
        await b.tools()
    assert b.status().startswith("error")


async def test_disabled_backend_refuses(demo_cfg):
    b = Backend(demo_cfg(enabled=False))
    assert b.status() == "disabled"
    with pytest.raises(BackendError, match="disabled"):
        await b.tools()


async def test_restarts_after_the_process_dies(demo_cfg):
    b = Backend(demo_cfg())
    try:
        await b.tools()
        with pytest.raises(BackendError):
            await b.call("die", {})
        for _ in range(50):  # let the task notice the dead process
            if not b.connected:
                break
            await asyncio.sleep(0.1)
        res = await b.call("add", {"a": 1, "b": 1})  # a fresh process starts transparently
        assert res.content[0].text == "2"
    finally:
        await b.stop()


async def test_slow_start_times_out(tmp_path):
    script = tmp_path / "hang.py"
    script.write_text("import time\ntime.sleep(60)\n")
    b = Backend(Cfg(name="hang", command=sys.executable, args=[str(script)]), start_timeout=1.5)
    with pytest.raises(BackendError, match="did not start"):
        await b.tools()
