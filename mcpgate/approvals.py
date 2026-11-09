"""The approvals queue: a risky tool call waits here until the owner decides, in the admin UI.

The model is never given anything it could use to approve its own call: no code, no id. It is told the request is
waiting and to retry the identical call. An approval applies to exactly one tool + arguments, runs once, and expires.
The queue lives in memory: pending requests survive a UI reload but are lost when the service restarts, and are
never approved automatically."""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections import deque
from dataclasses import dataclass, field

from .audit import _SECRET_KEY

TTL = 300.0           # a request, or an approval nobody used, lives 5 minutes
DENIED_MEMORY = 300.0  # after a denial, an identical call is refused for this long instead of asking again
WAIT = 45.0           # how long call_tool holds the line for a decision before telling the model to retry
MAX_PENDING = 50
MAX_ARGS_JSON = 100_000
SHOW_LIMIT = 20_000
MAX_GRANT_MINUTES = 60


class Refused(Exception):
    """Raised to the hub; the message is what the model is told."""


@dataclass
class Request:
    id: str
    tool: str
    key: str
    args: dict
    created: float           # wall clock, for display
    expires: float           # on the queue's clock
    state: str = "pending"   # pending | approved | denied | expired
    grant_minutes: int = 0
    event: asyncio.Event = field(default_factory=asyncio.Event)


def mask(value, depth: int = 0):
    """Arguments as the owner sees them: exact, except values under secret-looking keys."""
    if depth > 12:
        return "…"
    if isinstance(value, dict):
        return {k: ("***" if _SECRET_KEY.search(str(k)) else mask(v, depth + 1)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v, depth + 1) for v in value]
    return value


class Approvals:
    def __init__(self, clock=time.monotonic, wall=time.time, audit=None, scrub=None, wait: float = WAIT, ttl: float = TTL):
        self.clock, self.wall, self.wait, self.ttl = clock, wall, wait, ttl
        self.audit = audit or (lambda **_: None)
        self.scrub = scrub or (lambda text: text)
        self.by_key: dict[str, Request] = {}
        self.grants: dict[str, tuple[float, str]] = {}      # key -> (until, tool)
        self.history: deque[dict] = deque(maxlen=30)

    # -- bookkeeping ---------------------------------------------------------------
    def _sweep(self) -> None:
        now = self.clock()
        for key, g in list(self.grants.items()):
            if g[0] <= now:
                del self.grants[key]
        for key, r in list(self.by_key.items()):
            if r.state == "expired" and now > r.expires + DENIED_MEMORY:
                del self.by_key[key]          # nobody retried: forget it
                continue
            if r.expires > now:
                continue
            if r.state in ("pending", "approved"):
                was = r.state
                r.state = "expired"
                r.event.set()
                self._record(r, "expired")
                self.audit(event="approval_expired", tool=r.tool, id=r.id, was=was)
            if r.state in ("denied",):
                del self.by_key[key]          # the refusal has been remembered long enough
        # expired entries stay until reported once to the retrying model, then go (see gate)

    def _record(self, r: Request, state: str, minutes: int = 0) -> None:
        self.history.appendleft({"id": r.id, "tool": r.tool, "state": state, "minutes": minutes, "at": self.wall()})

    def _create(self, tool: str, key: str, args: dict) -> Request:
        if len([r for r in self.by_key.values() if r.state == "pending"]) >= MAX_PENDING:
            raise Refused("There are too many approval requests waiting. Ask the owner to clear the queue, then try again.")
        try:
            size = len(json.dumps(args, default=str))
        except (TypeError, ValueError):
            size = MAX_ARGS_JSON + 1
        if size > MAX_ARGS_JSON:
            raise Refused("The arguments are too large to be shown to the owner for approval, so this call cannot run.")
        r = Request(secrets.token_hex(8), tool, key, args, self.wall(), self.clock() + self.ttl)
        self.by_key[key] = r
        self.audit(event="approval_requested", tool=tool, args=args, id=r.id)
        return r

    # -- the model's side ------------------------------------------------------------
    async def gate(self, tool: str, key: str, args: dict) -> None:
        """Return when this exact call may run; raise Refused with a message for the model otherwise."""
        deadline = self.clock() + self.wait
        while True:
            self._sweep()
            now = self.clock()
            if key in self.grants:
                return
            r = self.by_key.get(key)
            if r is None:
                r = self._create(tool, key, args)
            if r.state == "approved":
                del self.by_key[key]                       # single use
                return
            if r.state == "denied":
                raise Refused("The owner denied this call. Do not retry it; ask the user what they want to do instead.")
            if r.state == "expired":
                del self.by_key[key]
                raise Refused("The approval request expired without an answer. Ask the user, then call again to ask for approval again.")
            remaining = deadline - now
            if remaining > 0:
                try:
                    await asyncio.wait_for(r.event.wait(), remaining)
                    continue
                except asyncio.TimeoutError:
                    pass
            raise Refused(f"{tool} is waiting for the owner's approval. Tell the user it needs their approval, "
                          "then retry the identical call shortly.")

    # -- the owner's side ----------------------------------------------------------------
    def pending(self) -> list[Request]:
        self._sweep()
        return sorted((r for r in self.by_key.values() if r.state == "pending"), key=lambda r: r.created)

    def _find(self, rid: str) -> Request:
        self._sweep()
        for r in self.by_key.values():
            if r.id == rid:
                return r
        raise KeyError(rid)

    def approve(self, rid: str, minutes: int = 0) -> Request:
        r = self._find(rid)
        if r.state != "pending":
            raise ValueError(f"already {r.state}")
        if not isinstance(minutes, int) or isinstance(minutes, bool) or not 0 <= minutes <= MAX_GRANT_MINUTES:
            raise ValueError(f"minutes must be between 0 and {MAX_GRANT_MINUTES}")
        r.state, r.grant_minutes = "approved", minutes
        r.expires = self.clock() + self.ttl
        if minutes:
            self.grants[r.key] = (self.clock() + minutes * 60, r.tool)
            del self.by_key[r.key]       # the grant replaces the single-use approval
        r.event.set()
        self._record(r, "approved", minutes)
        self.audit(event="approval_approved", tool=r.tool, args=r.args, id=r.id, minutes=minutes)
        return r

    def deny(self, rid: str) -> Request:
        r = self._find(rid)
        if r.state != "pending":
            raise ValueError(f"already {r.state}")
        r.state = "denied"
        r.expires = self.clock() + DENIED_MEMORY
        r.event.set()
        self._record(r, "denied")
        self.audit(event="approval_denied", tool=r.tool, args=r.args, id=r.id)
        return r

    def view(self, r: Request) -> dict:
        text = self.scrub(json.dumps(mask(r.args), indent=2, ensure_ascii=False, default=str))
        cut = len(text) > SHOW_LIMIT
        return {"id": r.id, "tool": r.tool, "backend": r.tool.split(".", 1)[0], "args": text[:SHOW_LIMIT], "args_cut": cut,
                "requested_ago": max(0, int(self.wall() - r.created)), "expires_in": max(0, int(r.expires - self.clock()))}

    def snapshot(self) -> dict:
        pend = [self.view(r) for r in self.pending()]
        now = self.wall()
        recent = [{**h, "ago": max(0, int(now - h["at"]))} for h in self.history]
        for h in recent:
            h.pop("at")
        return {"pending": pend, "count": len(pend), "recent": recent}
