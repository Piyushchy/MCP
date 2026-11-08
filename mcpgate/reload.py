"""Keeping a running gateway in step with its config file."""
from __future__ import annotations

import asyncio
import signal
from pathlib import Path

from . import loader
from .config import ConfigError
from .hub import Hub


class Reloader:
    """Re-reads the config when it changes (or on SIGHUP) and applies it with Hub.reload.

    A config that fails to load never replaces the working one: the error is kept in ``error`` so a
    UI can show it, and cleared by the next good load."""

    def __init__(self, hub: Hub, path: Path | str | None = None, interval: float = 2.0, extra_files=None, on_reload=None):
        self.hub, self.path, self.interval = hub, path, interval
        self.extra_files = list(extra_files or [])
        self.on_reload = on_reload  # optional async hook(summary) after a successful reload
        self.error = ""
        self.last: dict | None = None
        self.hup_installed = False
        self._sig = None
        self._task: asyncio.Task | None = None

    async def check(self, force: bool = False) -> bool:
        extra = self.extra_files + ([self.hub.secrets.path] if self.hub.secrets else [])
        sig = loader.signature(self.path, extra)
        if not force and sig == self._sig:
            return False
        self._sig = sig
        try:
            settings = loader.load_settings(self.path)
            self.last = await self.hub.reload(settings)
            self.last["secrets_restarted"] = await self.hub.apply_secret_changes()
            self.error = ""
            if self.on_reload:
                await self.on_reload(self.last)
        except (ConfigError, OSError, ValueError) as e:
            self.error = str(e)
            return False
        return True

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.interval)
            try:
                await self.check()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 - the watcher must never die
                self.error = f"{type(e).__name__}: {e}"

    def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._task = loop.create_task(self._loop(), name="config-reloader")
        try:
            loop.add_signal_handler(signal.SIGHUP, lambda: loop.create_task(self.check(force=True)))
            self.hup_installed = True
        except (NotImplementedError, RuntimeError, ValueError):
            self.hup_installed = False  # not the main thread, or no SIGHUP on this system

    async def stop(self) -> None:
        if self.hup_installed:
            try:
                asyncio.get_running_loop().remove_signal_handler(signal.SIGHUP)
            except (NotImplementedError, RuntimeError, ValueError):
                pass
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
