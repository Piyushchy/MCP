"""Audit page API: filtered view of the log, download, and on/off + size settings."""
from __future__ import annotations

import asyncio
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse

from .. import auditlog
from .api import body
from .app import Spec
from .context import AdminContext
from .session import AuthError

STATUSES = ["ok", "cached", "tool_error", "error", "refused", "awaiting_approval"]


def routes(ctx: AdminContext) -> list[Spec]:
    def path() -> Path | None:
        return ctx.hub.audit.path

    def settings() -> dict:
        s = ctx.hub.settings
        return {"enabled": bool(s.audit_log), "max_mb": s.audit_max_mb, "keep": s.audit_keep, "file": s.audit_log}

    def text(request: Request, key: str) -> str:
        v = request.query_params.get(key, "")
        if len(v) > 200:
            raise AuthError(400, f"{key} is too long")
        return v

    def number(request: Request, key: str):
        v = request.query_params.get(key)
        if v in (None, ""):
            return None
        try:
            n = float(v)
        except ValueError:
            raise AuthError(400, f"{key} must be a number") from None
        if n != n or n in (float("inf"), float("-inf")):
            raise AuthError(400, f"{key} must be a number")
        return n

    async def show(request: Request) -> Response:
        p = path()
        out = {"settings": settings(), "backends": sorted(ctx.hub.settings.backends), "statuses": STATUSES, "files": [],
               "entries": [], "next": None, "scanned": 0, "bad": 0, "stale": False}
        if p is None:
            return JSONResponse(out)
        kind = text(request, "kind")
        if kind and kind not in auditlog.KINDS:
            raise AuthError(400, "unknown kind")
        limit = number(request, "limit")
        limit = 100 if limit is None else int(limit)
        if not 1 <= limit <= 200:
            raise AuthError(400, "limit must be 1 to 200")
        try:
            res = await asyncio.to_thread(
                auditlog.page, p, limit=limit, cursor=request.query_params.get("cursor") or None, since=number(request, "since"),
                until=number(request, "until"), backend=text(request, "backend"), tool=text(request, "tool"),
                status=text(request, "status"), kind=kind, q=text(request, "q"))
        except ValueError:
            raise AuthError(400, "bad cursor") from None
        out.update(res, files=auditlog.info(p))
        return JSONResponse(out)

    async def download(request: Request) -> Response:
        p = path()
        if p is None or not auditlog.log_files(p):
            raise AuthError(404, "there is no audit log yet")
        return StreamingResponse(auditlog.stream(p), media_type="application/x-ndjson",
                                 headers={"content-disposition": 'attachment; filename="mcpgate-audit.jsonl"', "cache-control": "no-store"})

    async def save(request: Request) -> Response:
        d = await body(request)
        extra = set(d) - {"enabled", "max_mb", "keep"}
        if extra or not d:
            raise AuthError(400, "send enabled, max_mb and/or keep")
        for key, lo, hi in (("max_mb", 1, 1000), ("keep", 1, 50)):
            if key in d and (isinstance(d[key], bool) or not isinstance(d[key], int) or not lo <= d[key] <= hi):
                raise AuthError(400, f"{key} must be a whole number from {lo} to {hi}")
        if "enabled" in d and not isinstance(d["enabled"], bool):
            raise AuthError(400, "enabled must be true or false")

        def change(s):
            if "enabled" in d:
                s.audit_log = (s.audit_log or str(Path(ctx.config_file).parent / "audit.jsonl")) if d["enabled"] else ""
            if "max_mb" in d:
                s.audit_max_mb = d["max_mb"]
            if "keep" in d:
                s.audit_keep = d["keep"]
        # the audit line for turning it off is written first, while it is still on
        ctx.audit(event="admin_audit_settings", **{k: v for k, v in d.items()})
        await ctx.edit(change)
        return JSONResponse({"settings": settings()})

    return [Spec("/api/audit", ("GET",), show), Spec("/api/audit/download", ("GET",), download),
            Spec("/api/audit/settings", ("POST",), save, csrf=True)]
