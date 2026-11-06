"""Keep what goes back to the model small: short descriptions, capped results, pageable overflow."""
from __future__ import annotations

import secrets
from collections import OrderedDict


def short(text: str | None, limit: int = 160) -> str:
    """First sentence or line of a description, cut to ``limit`` characters."""
    if not text:
        return ""
    line = " ".join(text.strip().split())
    for end in (". ", "! ", "? "):
        i = line.find(end)
        if 0 < i < limit:
            return line[: i + 1]
    return line if len(line) <= limit else line[: limit - 1].rstrip() + "…"


class ResultStore:
    """Holds the full text of results that were cut, so the model can page through them."""

    def __init__(self, keep: int = 50):
        self.keep = keep
        self._items: OrderedDict[str, str] = OrderedDict()

    def put(self, text: str) -> str:
        rid = secrets.token_urlsafe(6)
        self._items[rid] = text
        while len(self._items) > self.keep:
            self._items.popitem(last=False)
        return rid

    def read(self, rid: str, offset: int = 0, length: int = 10000) -> tuple[str, int]:
        if rid not in self._items:
            raise KeyError(rid)
        text = self._items[rid]
        offset = max(0, offset)
        return text[offset: offset + max(1, length)], len(text)


def cap(text: str, limit: int, store: ResultStore) -> str:
    """Return ``text`` unchanged if it fits, otherwise the head plus a note on how to read the rest."""
    if len(text) <= limit:
        return text
    rid = store.put(text)
    return (f"{text[:limit]}\n\n[Result cut: showing {limit} of {len(text)} characters. "
            f"Call read_result with result_id=\"{rid}\" and offset={limit} for the rest.]")
