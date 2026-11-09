"""Hashed credentials for the gateway: the OAuth approval passphrase, the static bearer token, and
(later) the admin UI passphrase. Only hashes are stored, in ``auth.json`` next to the config (mode 600).

Passphrases are low-entropy, so they use scrypt with a random salt. The static token is a long random
value we generate, so a plain SHA-256 is enough and keeps every request fast.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from .config import ConfigError, config_path

MIN_PASSPHRASE = 12
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


def auth_path() -> Path:
    return config_path().parent / "auth.json"


def hash_passphrase(value: str) -> dict:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(value.encode(), salt=salt, dklen=32, **_SCRYPT)
    return {"algo": "scrypt", **{k: v for k, v in _SCRYPT.items()},
            "salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(digest).decode()}


def verify_passphrase(value: str, rec: dict) -> bool:
    try:
        salt = base64.b64decode(rec["salt"])
        want = base64.b64decode(rec["hash"])
        got = hashlib.scrypt(value.encode(), salt=salt, dklen=len(want), n=rec["n"], r=rec["r"], p=rec["p"])
    except (KeyError, ValueError, TypeError):
        return False
    return hmac.compare_digest(got, want)


def hash_token(value: str) -> dict:
    return {"algo": "sha256", "hash": hashlib.sha256(value.encode()).hexdigest()}


def verify_token(value: str, rec: dict) -> bool:
    want = rec.get("hash", "") if isinstance(rec, dict) else ""
    return hmac.compare_digest(hashlib.sha256(value.encode()).hexdigest(), want)


def new_token() -> str:
    return secrets.token_urlsafe(32)


class AuthStore:
    """Named hashed credentials. Re-reads the file when another process (the CLI, the UI) changes it."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path).expanduser() if path else auth_path()
        self.records: dict[str, dict] = {}
        self.error = ""
        self._mtime = None
        self._sync(first=True)

    def _sync(self, first: bool = False) -> None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            if self._mtime is not None:
                self.records, self._mtime = {}, None
            return
        if st.st_mode & 0o077:
            msg = f"{self.path} is readable by other users; run: chmod 600 {self.path}"
            if first:
                raise ConfigError(msg)
            self.error, self.records = msg, {}   # refuse to use it until fixed
            self._mtime = None                   # and re-read it once the permissions are right
            return
        self.error = ""
        if st.st_mtime_ns != self._mtime:
            try:
                self.records = dict(json.loads(self.path.read_text()).get("records", {}))
            except (OSError, ValueError):
                self.records = {}
            self._mtime = st.st_mtime_ns

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"records": self.records}, f)
        tmp.replace(self.path)
        self._mtime = self.path.stat().st_mtime_ns

    # -- reading ---------------------------------------------------------
    def has(self, name: str) -> bool:
        self._sync()
        return name in self.records

    def when(self, name: str) -> float | None:
        self._sync()
        return self.records.get(name, {}).get("updated")

    def verify(self, name: str, value: str) -> bool:
        self._sync()
        rec = self.records.get(name)
        if not rec or not isinstance(value, str):
            return False
        if rec.get("expires") and time.time() > rec["expires"]:
            return False
        return verify_passphrase(value, rec) if rec.get("algo") == "scrypt" else verify_token(value, rec)

    # -- writing ---------------------------------------------------------
    def set_passphrase(self, name: str, value: str) -> None:
        if len(value) < MIN_PASSPHRASE:
            raise ConfigError(f"the passphrase must be at least {MIN_PASSPHRASE} characters")
        self._sync()
        self.records[name] = {**hash_passphrase(value), "updated": time.time()}
        self._save()

    def set_token(self, name: str, value: str, ttl: float | None = None) -> None:
        self._sync()
        self.records[name] = {**hash_token(value), "updated": time.time(), **({"expires": time.time() + ttl} if ttl else {})}
        self._save()

    def clear(self, name: str) -> bool:
        self._sync()
        found = self.records.pop(name, None) is not None
        if found:
            self._save()
        return found
