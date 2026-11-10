"""Append-only JSONL record of every tool call, with secrets in arguments blanked out."""
from __future__ import annotations

import json
import os
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:   # not on Windows; there the in-process lock still applies
    fcntl = None

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_KEEP = 5
_THREAD_LOCK = threading.Lock()

_SECRET_KEY = re.compile(r"token|secret|password|passwd|authorization|api[_-]?key|credential|cookie", re.I)


def redact(value, depth: int = 0):
    if depth > 4:
        return "…"
    if isinstance(value, dict):
        return {k: ("***" if _SECRET_KEY.search(str(k)) else redact(v, depth + 1)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value[:20]]
    if isinstance(value, str) and len(value) > 200:
        return value[:200] + f"…(+{len(value) - 200} chars)"
    return value


def rotated(path: Path, n: int) -> Path:
    return path.with_name(f"{path.name}.{n}")


class Audit:
    """Appends one JSON line per event. When the file reaches ``max_bytes`` it is renamed to .1 (older ones shift up,
    the oldest beyond ``keep`` is deleted). Rotation and writing happen under one lock, so no line is lost or split,
    even with several writers (the service and the CLI)."""

    def __init__(self, path: str = "", scrub=None, max_bytes: int = DEFAULT_MAX_BYTES, keep: int = DEFAULT_KEEP):
        self.path = Path(path).expanduser() if path else None
        self.scrub = scrub   # optional text filter applied to every line (blanks stored secret values)
        self.max_bytes, self.keep = max_bytes, keep

    @contextmanager
    def _locked(self):
        with _THREAD_LOCK:
            if fcntl is None:
                yield
                return
            fd = os.open(self.path.with_name(self.path.name + ".lock"), os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)      # closing releases the lock

    def _rotate_if_needed(self, incoming: int) -> None:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return
        if size == 0 or size + incoming <= self.max_bytes:
            return
        rotated(self.path, self.keep).unlink(missing_ok=True)
        for n in range(self.keep - 1, 0, -1):
            if rotated(self.path, n).exists():
                os.replace(rotated(self.path, n), rotated(self.path, n + 1))
        os.replace(self.path, rotated(self.path, 1))

    def log(self, **fields) -> None:
        if not self.path:
            return
        if "args" in fields:
            fields["args"] = redact(fields["args"])
        fields = {"ts": round(time.time(), 3), **fields}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(fields, default=str)
            data = ((self.scrub(line) if self.scrub else line) + "\n").encode()
            with self._locked():
                self._rotate_if_needed(len(data))
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    os.write(fd, data)         # one write call: the line is never interleaved with another
                finally:
                    os.close(fd)
        except OSError:
            pass  # auditing must never break a tool call
