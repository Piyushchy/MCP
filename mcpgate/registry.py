"""Searching the combined tool list of all backends."""
from __future__ import annotations

import math
import re

from .backends import ToolInfo

_WORD = re.compile(r"[a-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def words(text: str) -> list[str]:
    return _WORD.findall(_CAMEL.sub(" ", text).lower())


def split_name(full: str) -> tuple[str, str]:
    """'github.create_issue' -> ('github', 'create_issue')."""
    backend, dot, tool = full.partition(".")
    if not dot or not backend or not tool:
        raise ValueError(f"tool names look like 'backend.tool', got {full!r}")
    return backend, tool


def rank(tools: list[ToolInfo], query: str, limit: int = 8) -> list[ToolInfo]:
    """Best matches first. An empty query lists tools alphabetically."""
    q = words(query)
    if not q:
        return sorted(tools, key=lambda t: t.full)[:limit]
    exact = [t for t in tools if t.full.lower() == query.strip().lower()]
    docs = []
    df: dict[str, int] = {}
    for t in tools:
        name_w = set(words(t.name))
        back_w = set(words(t.backend))
        desc_w = set(words(t.description))
        docs.append((t, name_w, back_w, desc_w))
        for w in name_w | back_w | desc_w:
            df[w] = df.get(w, 0) + 1
    n = max(len(tools), 1)
    scored = []
    for t, name_w, back_w, desc_w in docs:
        score, hit = 0.0, 0
        for w in q:
            idf = math.log(1 + n / (1 + df.get(w, 0)))
            s = 0.0
            if w in name_w:
                s = 4 * idf
            elif any(w in nw or nw in w for nw in name_w if len(nw) >= 3 and len(w) >= 3):
                s = 2.5 * idf
            if w in back_w:
                s = max(s, 2 * idf)
            if w in desc_w:
                s += 1 * idf
            if s:
                hit += 1
            score += s
        if hit:
            score *= 1 + 0.5 * (hit - 1) / max(len(q), 1) if len(q) > 1 else 1
            if hit == len(q) and len(q) > 1:
                score *= 1.5
            scored.append((score, t))
    scored.sort(key=lambda x: (-x[0], x[1].full))
    out = [t for _, t in scored]
    for t in exact:  # an exact full name always comes first
        if t in out:
            out.remove(t)
        out.insert(0, t)
    return out[:limit]
