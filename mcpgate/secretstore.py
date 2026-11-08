"""Credentials that backends need (a GitHub token, a docs API key), kept out of the config file.

The config only ever says ``${NAME}``. The value is looked up in the real environment first and then here.
It is plaintext on disk, protected by file permissions (mode 600) like an SSH key; there is deliberately no
call, in the CLI or the admin UI, that returns a stored value. ``get`` exists only for starting backends.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

from .config import ConfigError, config_path

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
MAX_VALUE = 8192
MIN_SCRUB = 6   # shorter values would blank out ordinary words in error text


def secrets_path() -> Path:
    return config_path().parent / "secrets.json"


class SecretStore:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path).expanduser() if path else secrets_path()
        self.items: dict[str, dict] = {}
        self.error = ""
        self._mtime = None
        self._sync(first=True)

    def _sync(self, first: bool = False) -> None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            if self._mtime is not None:
                self.items, self._mtime = {}, None
            return
        if st.st_mode & 0o077:
            msg = f"{self.path} is readable by other users; run: chmod 600 {self.path}"
            if first:
                raise ConfigError(msg)
            self.error, self.items, self._mtime = msg, {}, None   # unusable until fixed
            return
        self.error = ""
        if st.st_mtime_ns != self._mtime:
            try:
                self.items = dict(json.loads(self.path.read_text()).get("items", {}))
            except (OSError, ValueError):
                self.items = {}
            self._mtime = st.st_mtime_ns

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"items": self.items}, f)
        tmp.replace(self.path)
        self._mtime = self.path.stat().st_mtime_ns

    # -- metadata only (safe to show) -------------------------------------
    def names(self) -> list[dict]:
        self._sync()
        return [{"name": n, "updated": v.get("updated")} for n, v in sorted(self.items.items())]

    def has(self, name: str) -> bool:
        self._sync()
        return name in self.items

    # -- writing -----------------------------------------------------------
    def set(self, name: str, value: str) -> None:
        if not NAME_RE.match(name):
            raise ConfigError("a secret name is letters, digits and '_' (it must not start with a digit)")
        if not value or "\x00" in value or len(value) > MAX_VALUE:
            raise ConfigError(f"a secret value must be 1-{MAX_VALUE} characters and contain no NUL")
        self._sync()
        self.items[name] = {"value": value, "updated": time.time()}
        self._save()

    def delete(self, name: str) -> bool:
        self._sync()
        found = self.items.pop(name, None) is not None
        if found:
            self._save()
        return found

    # -- internal use only -------------------------------------------------
    def get(self, name: str) -> str | None:
        """Used when starting a backend. Never exposed through the CLI or the admin UI."""
        self._sync()
        rec = self.items.get(name)
        return rec["value"] if rec else None

    def fingerprints(self) -> dict[str, str]:
        """name -> short hash of the value, to tell which secrets changed without handling the values."""
        self._sync()
        return {n: hashlib.sha256(v["value"].encode()).hexdigest()[:16] for n, v in self.items.items()}

    def scrub(self, text: str) -> str:
        """Blank out any stored value that appears in ``text`` (error messages, logs)."""
        if not text:
            return text
        self._sync()
        for v in sorted((r["value"] for r in self.items.values() if len(r["value"]) >= MIN_SCRUB), key=len, reverse=True):
            text = text.replace(v, "***")
        return text
