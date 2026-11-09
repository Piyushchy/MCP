"""Approvals inbox API. Approving needs a session and a CSRF token like every other change."""
from __future__ import annotations

import re

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .api import body
from .app import Spec
from .context import AdminContext
from .session import AuthError

ID_RE = re.compile(r"^[0-9a-f]{16}$")


def routes(ctx: AdminContext) -> list[Spec]:
    def queue():
        q = ctx.hub.approvals
        if q is None:
            raise AuthError(409, "approvals are handled here only when mcpgate runs as the service (mcpgate serve --service)")
        return q

    def rid(request: Request) -> str:
        v = request.path_params["rid"]
        if not ID_RE.match(v):
            raise AuthError(404, "no such request")
        return v

    async def listing(request: Request) -> Response:
        q = ctx.hub.approvals
        if q is None:
            return JSONResponse({"pending": [], "count": 0, "recent": [], "available": False})
        return JSONResponse({**q.snapshot(), "available": True})

    async def approve(request: Request) -> Response:
        q, i = queue(), rid(request)
        d = await body(request)
        try:
            r = q.approve(i, d.get("minutes", 0))
        except KeyError:
            raise AuthError(404, "that request is no longer waiting (it was decided or expired)") from None
        except ValueError as e:
            raise AuthError(409 if "already" in str(e) else 400, str(e)) from None
        return JSONResponse({"id": r.id, "state": "approved", "minutes": r.grant_minutes})

    async def deny(request: Request) -> Response:
        q, i = queue(), rid(request)
        try:
            r = q.deny(i)
        except KeyError:
            raise AuthError(404, "that request is no longer waiting (it was decided or expired)") from None
        except ValueError as e:
            raise AuthError(409, str(e)) from None
        return JSONResponse({"id": r.id, "state": "denied"})

    return [
        Spec("/api/approvals", ("GET",), listing),
        Spec("/api/approvals/{rid}/approve", ("POST",), approve, csrf=True),
        Spec("/api/approvals/{rid}/deny", ("POST",), deny, csrf=True),
    ]
