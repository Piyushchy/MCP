"""What the admin routes share: the running hub, the config file, the reloader and the stores."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable

from .. import config as cfgmod
from ..config import ConfigError, Settings
from .session import AuthError


class AdminContext:
    def __init__(self, hub, config_file: Path | str | None, reloader, secrets, auth):
        self.hub, self.reloader, self.secrets, self.auth = hub, reloader, secrets, auth
        self.config_file = Path(config_file).expanduser() if config_file else cfgmod.config_path()
        self.lock = asyncio.Lock()   # one config edit at a time

    def audit(self, **fields) -> None:
        self.hub.audit.log(**fields)

    def file_settings(self) -> Settings:
        """The config file as written (drop-in servers are not part of it)."""
        return cfgmod.load(self.config_file)

    async def edit(self, change: Callable[[Settings], None]) -> None:
        """Load the file, apply ``change``, save it and apply it to the running gateway. A change the
        reloader refuses is rolled back, so the file never holds something the gateway cannot run."""
        async with self.lock:
            before = self.config_file.read_bytes() if self.config_file.exists() else None
            s = self.file_settings()
            try:
                change(s)
                cfgmod.save(s, self.config_file)
            except ConfigError as e:
                raise AuthError(400, str(e)) from None
            await self.reloader.check(force=True)
            if self.reloader.error:
                msg = self.reloader.error
                if before is None:
                    self.config_file.unlink(missing_ok=True)
                else:
                    self.config_file.write_bytes(before)
                self.config_file.chmod(0o600)
                await self.reloader.check(force=True)
                raise AuthError(400, f"that change was not applied: {msg}")
