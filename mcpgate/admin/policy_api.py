"""Tool permissions API: show a backend's real tools with their state, preview a change, save it."""
from __future__ import annotations

import asyncio

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..config import NAME_RE
from .api import body
from .app import Spec
from .context import AdminContext
from .policyedit import STATES, Conflict, Rules, apply, options, state_of
from .session import AuthError

MAX_CHANGES = 500
DESC_LIMIT = 300


def _clip(text: str) -> str:
    line = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    return line[:DESC_LIMIT] + ("…" if len(line) > DESC_LIMIT else "")


def payload(ctx: AdminContext, b, rules: Rules | None = None) -> dict:
    cfg = b.cfg
    saved = Rules(list(cfg.allow), list(cfg.deny), list(cfg.confirm))
    rules = rules or saved
    tools = {t.name: t for t in (b._tools or [])}
    loaded = b._tools is not None
    why = ""
    if cfg.source == "custom":
        why = "This drop-in server's rules are not stored in the config, so they cannot be edited here."
    elif not cfg.enabled:
        why = "This backend is disabled. Enable it to load its tools and edit their rules."
    elif not loaded:
        why = "The tools are not loaded yet. Load them to edit the rules."
    elif b.error and not b.connected:
        why = f"This backend cannot be reached right now ({ctx.secrets.scrub(b.error)}), so its tools cannot be edited. The saved rules are shown."
    rows = []
    for name in sorted(tools):
        t = tools[name]
        st, reason = state_of(rules, name, t.destructive)
        rows.append({"name": name, "description": _clip(t.description), "read_only": t.read_only, "destructive": t.destructive,
                     "state": st, "reason": reason, "options": options(rules, tools, name)})
    return {"name": b.name, "loaded": loaded, "editable": not why, "why": why,
            "rules": {"allow": rules.allow, "deny": rules.deny, "confirm": rules.confirm}, "tools": rows,
            "model_sees": [r["name"] for r in rows if r["state"] != "block"],
            "needs_approval": [r["name"] for r in rows if r["state"] == "confirm"],
            "hidden": [r["name"] for r in rows if r["state"] == "block"]}


def routes(ctx: AdminContext) -> list[Spec]:
    def find(request: Request):
        name = request.path_params["name"]
        b = ctx.hub.backends.get(name) if NAME_RE.match(name) else None
        if b is None:
            raise AuthError(404, "no such backend")
        return b

    def parse(b, d: dict) -> tuple[Rules, dict, dict]:
        tools = {t.name: t for t in (b._tools or [])}
        changes = d.get("changes", {})
        remove = d.get("remove", {})
        if not isinstance(changes, dict) or len(changes) > MAX_CHANGES or not isinstance(remove, dict):
            raise AuthError(400, "invalid request")
        for tool, st in changes.items():
            if st not in STATES:
                raise AuthError(400, f"{st!r} is not a state")
            if tool not in tools:
                raise AuthError(400, "unknown tool: " + tool[:80])
        cur = Rules(list(b.cfg.allow), list(b.cfg.deny), list(b.cfg.confirm))
        for lst, items in remove.items():
            if lst not in ("allow", "deny", "confirm") or not isinstance(items, list):
                raise AuthError(400, "invalid request")
            for p in items:
                if p not in getattr(cur, lst):
                    raise AuthError(400, f"{p!r} is not in the {lst} rules")
        try:
            return apply(cur, tools, changes, remove), changes, remove
        except Conflict as e:
            raise AuthError(409, str(e)) from None

    def need_editable(b) -> None:
        p = payload(ctx, b)
        if not p["editable"]:
            raise AuthError(409, p["why"])

    async def show(request: Request) -> Response:
        return JSONResponse(payload(ctx, find(request)))

    async def load(request: Request) -> Response:
        b = find(request)
        if b.cfg.enabled:
            try:
                await asyncio.wait_for(b.tools(refresh=True), b.start_timeout + 5)
            except Exception:  # noqa: BLE001 - the payload explains it
                pass
        return JSONResponse(payload(ctx, b))

    async def preview(request: Request) -> Response:
        b = find(request)
        need_editable(b)
        new, _, _ = parse(b, await body(request))
        return JSONResponse(payload(ctx, b, new))

    async def save(request: Request) -> Response:
        b = find(request)
        need_editable(b)
        new, changes, remove = parse(b, await body(request))
        old = Rules(list(b.cfg.allow), list(b.cfg.deny), list(b.cfg.confirm))

        def change(s):
            cur = s.backends.get(b.name)
            if cur is None or Rules(cur.allow, cur.deny, cur.confirm).key() != old.key():
                raise AuthError(409, "the rules changed on disk while you were editing; reload the page")
            cur.allow, cur.deny, cur.confirm = new.allow, new.deny, new.confirm
        await ctx.edit(change)
        ctx.audit(event="admin_policy_change", backend=b.name, changes=changes, removed_patterns=remove)
        return JSONResponse(payload(ctx, ctx.hub.backends[b.name]))

    P = "/api/backends/{name}/policy"
    return [
        Spec(P, ("GET",), show),
        Spec(P + "/load", ("POST",), load, csrf=True),
        Spec(P + "/preview", ("POST",), preview, csrf=True),
        Spec(P + "/save", ("POST",), save, csrf=True),
    ]
