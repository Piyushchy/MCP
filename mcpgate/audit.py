"""Append-only JSONL record of every tool call, with secrets in arguments blanked out."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

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


class Audit:
    def __init__(self, path: str = ""):
        self.path = Path(path).expanduser() if path else None

    def log(self, **fields) -> None:
        if not self.path:
            return
        if "args" in fields:
            fields["args"] = redact(fields["args"])
        fields = {"ts": round(time.time(), 3), **fields}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(fields, default=str) + "\n")
        except OSError:
            pass  # auditing must never break a tool call
