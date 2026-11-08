"""UI-01: the gateway follows its config file without a restart."""
import asyncio
import os
import signal
import sys

import pytest

from mcpgate import config, loader
from mcpgate.config import Backend, Settings
from mcpgate.hub import GatewayError, Hub
from mcpgate.reload import Reloader
from tests.conftest import DEMO


def write(path, **backends):
    s = Settings(cache_ttl=60)
    for name, kw in backends.items():
        s.backends[name] = Backend(name=name, command=sys.executable, args=[DEMO], timeout=20, **kw)
    config.save(s, path)


@pytest.fixture
def cfgfile(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))  # keeps real drop-ins out
    return tmp_path / "config.toml"


async def start(cfgfile):
    hub = Hub(loader.load_settings(cfgfile))
    rl = Reloader(hub, cfgfile)
    await rl.check()
    return hub, rl


async def text(hub, name, args=None):
    return hub_text(await hub.call(name, args or {}))


def hub_text(blocks):
    return "\n".join(b.text for b in blocks if b.type == "text")


async def test_add_remove_enable_disable_apply_live(cfgfile):
    write(cfgfile, demo={})
    hub, rl = await start(cfgfile)
    try:
        assert await text(hub, "demo.add", {"a": 1, "b": 1}) == "2"
        write(cfgfile, demo={}, second={})
        assert await rl.check() and rl.last["added"] == ["second"]
        assert await text(hub, "second.echo", {"text": "hi"}) == "hi"
        write(cfgfile, demo={}, second={"enabled": False})
        await rl.check()
        with pytest.raises(GatewayError, match="disabled"):
            await text(hub, "second.echo", {"text": "hi"})
        write(cfgfile, demo={})
        await rl.check()
        assert rl.last["removed"] == ["second"] and "second" not in hub.backends
        with pytest.raises(GatewayError, match="No backend named"):
            await text(hub, "second.echo", {"text": "hi"})
    finally:
        await hub.stop()


async def test_an_unchanged_backend_keeps_its_process_but_a_changed_one_restarts(cfgfile):
    write(cfgfile, demo={})
    hub, rl = await start(cfgfile)
    hub.settings.cache_ttl = 0  # so the counter really reaches the process each time
    try:
        assert await text(hub, "demo.counter") == "1"
        write(cfgfile, demo={}, other={})           # unrelated change
        await rl.check()
        hub.settings.cache_ttl = 0
        assert await text(hub, "demo.counter") == "2"   # same process, counter continued
        write(cfgfile, demo={"env": {"X": "1"}}, other={})   # connection details changed
        await rl.check()
        assert rl.last["restarted"] == ["demo"]
        hub.settings.cache_ttl = 0
        assert await text(hub, "demo.counter") == "1"   # a fresh process
    finally:
        await hub.stop()


async def test_policy_changes_apply_to_the_very_next_call_even_if_cached(cfgfile):
    write(cfgfile, demo={})
    hub, rl = await start(cfgfile)
    try:
        assert await text(hub, "demo.echo", {"text": "a"}) == "a"
        assert await text(hub, "demo.echo", {"text": "a"}) == "a"   # now cached
        write(cfgfile, demo={"deny": ["echo"]})
        await rl.check()
        assert rl.last["policy_changed"] == ["demo"] and rl.last["restarted"] == []
        with pytest.raises(GatewayError, match="blocked"):
            await text(hub, "demo.echo", {"text": "a"})
        write(cfgfile, demo={"confirm": ["add"]})
        await rl.check()
        with pytest.raises(GatewayError, match="approval"):
            await text(hub, "demo.add", {"a": 1, "b": 2})
    finally:
        await hub.stop()


async def test_a_broken_file_never_replaces_a_working_config(cfgfile):
    write(cfgfile, demo={})
    hub, rl = await start(cfgfile)
    try:
        cfgfile.write_text("[backends.demo]\nbogus = 1\ncommand='x'\n")
        assert not await rl.check()
        assert "unknown key" in rl.error
        assert await text(hub, "demo.add", {"a": 2, "b": 2}) == "4"   # the old config still serves
        cfgfile.write_text("not = = toml")
        await rl.check()
        assert rl.error and await text(hub, "demo.echo", {"text": "ok"}) == "ok"
        write(cfgfile, demo={}, more={})
        assert await rl.check() and rl.error == ""
        assert "more" in hub.backends
    finally:
        await hub.stop()


async def test_a_reload_during_a_running_call_does_not_cancel_it(cfgfile):
    write(cfgfile, demo={})
    hub, rl = await start(cfgfile)
    try:
        task = asyncio.create_task(text(hub, "demo.nap", {"seconds": 1.5}))
        await asyncio.sleep(0.5)
        write(cfgfile, demo={"deny": ["die"]}, extra={})      # policy + an unrelated backend
        assert await rl.check()
        assert await task == "rested"
    finally:
        await hub.stop()


async def test_drop_in_files_are_picked_up_and_dropped(cfgfile, tmp_path):
    write(cfgfile, demo={})
    hub, rl = await start(cfgfile)
    drop = tmp_path / "xdg" / "mcpgate" / "custom"
    try:
        from mcpgate import custom
        custom.scaffold(Settings(), "greeter")
        assert await rl.check() and "greeter" in hub.backends
        assert await text(hub, "greeter.hello", {"who": "x"}) == "hello x"
        (drop / "greeter.py").unlink()
        assert await rl.check() and "greeter" not in hub.backends
    finally:
        await hub.stop()


async def test_the_background_watcher_notices_edits_by_itself(cfgfile):
    write(cfgfile, demo={})
    hub = Hub(loader.load_settings(cfgfile))
    rl = Reloader(hub, cfgfile, interval=0.1)
    rl.start()
    try:
        write(cfgfile, demo={}, late={})
        for _ in range(60):
            if "late" in hub.backends:
                break
            await asyncio.sleep(0.1)
        assert "late" in hub.backends
    finally:
        await rl.stop()
        await hub.stop()


async def test_sighup_forces_a_reload(cfgfile):
    write(cfgfile, demo={})
    hub = Hub(loader.load_settings(cfgfile))
    rl = Reloader(hub, cfgfile, interval=3600)   # the timer will not fire; only the signal can
    rl.start()
    try:
        if not rl.hup_installed:
            pytest.skip("SIGHUP handlers are unavailable here")
        await rl.check()
        write(cfgfile, demo={}, viahup={})
        os.kill(os.getpid(), signal.SIGHUP)
        for _ in range(50):
            if "viahup" in hub.backends:
                break
            await asyncio.sleep(0.1)
        assert "viahup" in hub.backends
    finally:
        await rl.stop()
        await hub.stop()


def test_connection_key_ignores_policy_and_description():
    a = Backend(name="x", command="c", allow=["*"])
    b = Backend(name="x", command="c", deny=["rm_*"], confirm=["a"], description="new", timeout=5)
    assert a.connection_key() == b.connection_key()
    assert a.connection_key() != Backend(name="x", command="other").connection_key()
    assert a.connection_key() != Backend(name="x", command="c", enabled=False).connection_key()
