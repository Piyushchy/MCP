"""Reading the audit log for the admin page: newest first, filtered, paged, never loading a whole file.

Files are read backwards in chunks, so showing the latest 100 lines of a huge log costs the same as of a small one.
A request scans at most MAX_SCAN lines; if the filter is rare it returns what it found plus a cursor to go on."""
from __future__ import annotations

import json
import os
import re
import zlib
from pathlib import Path

from .audit import rotated

CHUNK = 64 * 1024
MAX_SCAN = 100_000        # lines looked at per request
MAX_LINE = 64 * 1024      # a longer line is not parsed (the writer never produces one)
CURSOR_RE = re.compile(r"^(\d{1,3}):(\d{1,15}):(\d{1,20})$")
KINDS = {"call": lambda e: "event" not in e, "admin": lambda e: str(e.get("event", "")).startswith("admin_"),
         "approval": lambda e: str(e.get("event", "")).startswith("approval_")}


def log_files(path: Path) -> list[Path]:
    """The live file first, then .1, .2 ... (newest to oldest). Only files that exist."""
    out = [path] if path.exists() else []
    n = 1
    while n <= 50 and rotated(path, n).exists():
        out.append(rotated(path, n))
        n += 1
    return out


def info(path: Path) -> list[dict]:
    rows = []
    for p in log_files(path):
        try:
            st = p.stat()
        except OSError:
            continue
        rows.append({"name": p.name, "bytes": st.st_size, "modified": st.st_mtime})
    return rows


def backwards(f, end: int):
    """Yield (start_offset, line_bytes) for the lines that end before ``end``, last line first."""
    pos, buf, cover_end = end, b"", end
    while pos > 0:
        step = min(CHUNK, pos)
        pos -= step
        f.seek(pos)
        buf = f.read(step) + buf
        parts = buf.split(b"\n")
        buf = parts.pop(0)                      # may be the tail of a line that starts in an earlier chunk
        cur = cover_end
        for part in reversed(parts):
            start = cur - len(part)
            if part:
                yield start, part
            cur = start - 1
        cover_end = pos + len(buf)
    if buf:
        yield 0, buf


def backend_of(e: dict) -> str:
    if isinstance(e.get("backend"), str):
        return e["backend"]
    tool = e.get("tool")
    return tool.split(".", 1)[0] if isinstance(tool, str) and "." in tool else ""


def matcher(*, backend="", tool="", status="", kind="", q="", since=None, until=None):
    q = q.lower()

    def ok(e: dict, raw: bytes) -> bool:
        if kind and not KINDS[kind](e):
            return False
        if backend and backend_of(e) != backend:
            return False
        if tool and tool.lower() not in str(e.get("tool", "")).lower():
            return False
        if status and e.get("status") != status:
            return False
        ts = e.get("ts")
        if (since is not None or until is not None) and not isinstance(ts, (int, float)):
            return False
        if since is not None and ts < since:
            return False
        if until is not None and ts > until:
            return False
        return not q or q in raw.decode("utf-8", "replace").lower()
    return ok


def page(path: Path, *, limit: int = 100, cursor: str | None = None, since=None, **filters) -> dict:
    """One page, newest first. ``next`` is a cursor for the following (older) page, or None at the end."""
    ok = matcher(since=since, **filters)
    files = log_files(path)
    index, end = 0, None
    if cursor:
        m = CURSOR_RE.match(cursor)
        if not m:
            raise ValueError("bad cursor")
        index, end, ino = int(m.group(1)), int(m.group(2)), int(m.group(3))
        found = [i for i, p in enumerate(files) if _fid(p) == ino]
        if not found:                           # the file was rotated away since that page was shown
            return {"entries": [], "next": None, "scanned": 0, "bad": 0, "stale": True}
        index = found[0]
    entries, scanned, bad = [], 0, 0
    last = None
    while index < len(files):
        p = files[index]
        try:
            with open(p, "rb") as f:
                size = os.fstat(f.fileno()).st_size
                ino = _fid_of(f)
                for start, raw in backwards(f, min(end, size) if end is not None else size):
                    scanned += 1
                    last = f"{index}:{start}:{ino}"
                    entry = None
                    if len(raw) <= MAX_LINE:
                        try:
                            entry = json.loads(raw)
                        except ValueError:
                            entry = None
                    if not isinstance(entry, dict):
                        bad += 1
                    else:
                        if since is not None and isinstance(entry.get("ts"), (int, float)) and entry["ts"] < since:
                            return {"entries": entries, "next": None, "scanned": scanned, "bad": bad, "stale": False}
                        if ok(entry, raw):
                            entries.append(entry)
                    if len(entries) >= limit or scanned >= MAX_SCAN:
                        return {"entries": entries, "next": last, "scanned": scanned, "bad": bad, "stale": False}
        except OSError:
            pass
        index, end = index + 1, None
    return {"entries": entries, "next": None, "scanned": scanned, "bad": bad, "stale": False}


def _fid_of(f) -> int:
    """Identifies a file by its first line (every file starts with a unique timestamped line). Inode numbers
    are reused after a delete, so they cannot tell an old file from a new one."""
    f.seek(0)
    return zlib.crc32(f.read(512).split(b"\n", 1)[0])      # the first line never changes once written


def _fid(p: Path) -> int:
    try:
        with open(p, "rb") as f:
            return _fid_of(f)
    except OSError:
        return -1


def stream(path: Path):
    """Every kept line, oldest first, for the download."""
    for p in reversed(log_files(path)):
        try:
            with open(p, "rb") as f:
                while chunk := f.read(CHUNK):
                    yield chunk
        except OSError:
            continue
