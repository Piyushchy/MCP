"""The MCP server the AI client talks to: a handful of meta-tools instead of every backend tool."""
from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ContentBlock

from .config import Settings
from .hub import GatewayError, Hub
from .trim import short

INSTRUCTIONS = """\
This gateway reaches many tool servers through four tools, so their tool lists are not loaded up front.
1. search_tools(query) to find a tool (results show its exact name and arguments).
2. describe_tool(name) only if the arguments shown are not enough.
3. call_tool(name, arguments) to run it.
Names look like backend.tool. If a result says it was cut, read_result pages through the rest.
If a tool needs approval, tell the user what it will do and only then repeat the call with the confirm code."""

INSTRUCTIONS_OWNER_APPROVAL = INSTRUCTIONS.rsplit("If a tool needs approval", 1)[0] + (
    "If a tool needs approval, the call waits for the owner to approve it in their admin page. "
    "If it says it is still waiting, tell the user and retry the identical call shortly. Never change the arguments to get around a refusal.")


def _args(schema: dict) -> str:
    props = (schema or {}).get("properties", {}) or {}
    req = set((schema or {}).get("required", []) or [])
    return ", ".join(f"{k}{'*' if k in req else ''}" for k in props)


def build(settings: Settings, hub: Hub | None = None, oauth=None, **server_kwargs) -> tuple[FastMCP, Hub]:
    hub = hub or Hub(settings)
    if oauth is not None:  # remote OAuth (see oauth.py): the SDK serves the OAuth endpoints, we add /consent
        server_kwargs.update(auth_server_provider=oauth, auth=oauth.auth_settings)

    # The hub outlives any single client session, so whoever runs the server (see serve.py) stops it.
    app = FastMCP("mcpgate", instructions=INSTRUCTIONS_OWNER_APPROVAL if hub.approvals is not None else INSTRUCTIONS, **server_kwargs)

    @app.tool(structured_output=False)
    async def search_tools(query: str = "", backend: str | None = None, limit: int = 8, refresh: bool = False) -> str:
        """Find tools across all connected servers. Returns name, one-line purpose and argument names
        (* = required). Leave query empty to list tools alphabetically; use backend to look inside one server."""
        try:
            found, errors, total = await hub.search(query, backend, max(1, min(limit, 30)), refresh)
        except GatewayError as e:
            raise ToolError(str(e)) from None
        lines = []
        for t in found:
            flags = ""
            if hub.policies[t.backend].needs_confirm(t.name, t.destructive):
                flags = " [needs approval]"
            lines.append(f"{t.full} — {short(t.description)} ({_args(t.schema)}){flags}")
        head = f"{len(found)} of {total} tools" + (f" matching {query!r}" if query else "")
        out = [head] + lines if lines else [f"No tools match {query!r} ({total} tools searched)."]
        if errors:
            out.append("Unavailable: " + "; ".join(f"{n} ({m})" for n, m in errors.items()))
        return "\n".join(out)

    @app.tool(structured_output=False)
    async def describe_tool(name: str) -> str:
        """Full description and argument schema of one tool (name as backend.tool)."""
        try:
            t = await hub.find(name)
        except GatewayError as e:
            raise ToolError(str(e)) from None
        return json.dumps({
            "name": t.full, "description": t.description, "arguments": t.schema,
            "read_only": t.read_only,
            "needs_approval": hub.policies[t.backend].needs_confirm(t.name, t.destructive),
        }, indent=2)

    @app.tool(structured_output=False)
    async def call_tool(name: str, arguments: dict[str, Any] | None = None, confirm: str | None = None) -> list[ContentBlock]:
        """Run a tool by its full name (backend.tool). Pass confirm only when a previous call gave you a confirm code."""
        try:
            return await hub.call(name, arguments, confirm)
        except GatewayError as e:
            raise ToolError(str(e)) from None

    @app.tool(structured_output=False)
    async def list_backends() -> str:
        """The servers behind this gateway and whether each is reachable."""
        rows = hub.describe_backends()
        if not rows:
            return "No backends configured. Add one with: mcpgate add NAME --stdio COMMAND"
        return "\n".join(
            f"{r['name']}  {r['transport']}  {r['status']}" + (f"  tools={r['tools']}" if r["tools"] is not None else "")
            + (f"  {r['description']}" if r["description"] else "") for r in rows)

    @app.tool(structured_output=False)
    async def read_result(result_id: str, offset: int = 0, length: int = 10000) -> str:
        """Read more of a result that was cut (the cut note gives result_id and the offset to continue from)."""
        try:
            chunk, total = hub.store.read(result_id, offset, min(length, hub.settings.max_result_chars))
        except KeyError:
            raise ToolError("Unknown or expired result_id. Run the tool again.") from None
        end = offset + len(chunk)
        tail = f"\n\n[characters {offset}-{end} of {total}" + (f"; continue with offset={end}]" if end < total else "; end]")
        return chunk + tail

    if oauth is not None:
        oauth.install(app)
    return app, hub
