"""The hub: owns the backends, applies policy, and runs calls (cache, confirmation, audit)."""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time

from mcp.types import ContentBlock, ImageContent, TextContent

from .audit import Audit
from .backends import Backend, BackendError, ToolInfo
from .config import Settings
from .policy import Policy
from .registry import rank, split_name
from .trim import ResultStore, cap

CONFIRM_TTL = 300.0
CACHE_MAX = 200


class GatewayError(Exception):
    """Something the model should be told in plain words."""


class Hub:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.backends: dict[str, Backend] = {n: Backend(c, start_timeout=c.start_timeout) for n, c in settings.backends.items()}
        self.policies = {n: Policy(c.allow, c.deny, c.confirm) for n, c in settings.backends.items()}
        self.store = ResultStore()
        self.audit = Audit(settings.audit_log)
        self._cache: dict[str, tuple[float, list]] = {}
        self._pending: dict[str, tuple[str, str, float]] = {}

    async def stop(self) -> None:
        await asyncio.gather(*(b.stop() for b in self.backends.values()), return_exceptions=True)

    # -- catalogue ---------------------------------------------------------
    def _enabled(self, only: str | None = None) -> list[Backend]:
        if only:
            if only not in self.backends:
                raise GatewayError(f"No backend named {only!r}. Backends: {', '.join(sorted(self.backends)) or 'none'}.")
            return [self.backends[only]]
        return [b for b in self.backends.values() if b.cfg.enabled]

    async def catalog(self, only: str | None = None, refresh: bool = False) -> tuple[list[ToolInfo], dict[str, str]]:
        """Visible tools of the (enabled) backends, plus a map of backends that could not be reached."""
        backends = self._enabled(only)
        results = await asyncio.gather(
            *(b.tools(self.settings.tools_ttl, refresh) for b in backends), return_exceptions=True)
        tools: list[ToolInfo] = []
        errors: dict[str, str] = {}
        for b, res in zip(backends, results):
            if isinstance(res, BackendError):
                errors[b.name] = str(res).removeprefix(f"{b.name}: ")
            elif isinstance(res, BaseException):
                raise res
            else:
                pol = self.policies[b.name]
                tools.extend(t for t in res if pol.visible(t.name))
        return tools, errors

    async def search(self, query: str, backend: str | None = None, limit: int = 8,
                     refresh: bool = False) -> tuple[list[ToolInfo], dict[str, str], int]:
        tools, errors = await self.catalog(backend, refresh)
        return rank(tools, query, limit), errors, len(tools)

    async def find(self, full: str) -> ToolInfo:
        try:
            backend, tool = split_name(full)
        except ValueError as e:
            raise GatewayError(f"{e}. Use search_tools to find the exact name.") from None
        if backend not in self.backends:
            raise GatewayError(f"No backend named {backend!r}. Backends: {', '.join(sorted(self.backends)) or 'none'}.")
        try:
            tools = await self.backends[backend].tools(self.settings.tools_ttl)
        except BackendError as e:
            raise GatewayError(str(e)) from None
        pol = self.policies[backend]
        for t in tools:
            if t.name == tool and pol.visible(tool):
                return t
        raise GatewayError(f"{backend} has no tool {tool!r} (or it is blocked). Use search_tools with backend={backend!r}.")

    # -- calling -----------------------------------------------------------
    async def call(self, full: str, arguments: dict | None, confirm: str | None = None) -> list[ContentBlock]:
        started = time.monotonic()
        arguments = arguments or {}
        status = "error"
        try:
            info = await self.find(full)
            policy = self.policies[info.backend]
            key = hashlib.sha256(json.dumps([full, arguments], sort_keys=True, default=str).encode()).hexdigest()
            if policy.needs_confirm(info.name, info.destructive):
                self._check_confirm(full, key, confirm)
            elif confirm:
                pass  # a spare token is harmless

            ttl = self.settings.cache_ttl
            cacheable = info.read_only and ttl > 0
            if cacheable and key in self._cache and time.monotonic() - self._cache[key][0] < ttl:
                content, status = self._cache[key][1], "cached"
            else:
                try:
                    result = await self.backends[info.backend].call(info.name, arguments)
                except BackendError as e:
                    raise GatewayError(str(e)) from None
                content = list(result.content)
                if result.isError:
                    text = _join_text(content) or "the tool reported an error"
                    status = "tool_error"
                    raise GatewayError(cap(text, self.settings.max_result_chars, self.store))
                status = "ok"
                if cacheable:
                    self._remember(key, content)
            return self._shape(content)
        finally:
            self.audit.log(tool=full, args=arguments, status=status, ms=int((time.monotonic() - started) * 1000))

    def _remember(self, key: str, content: list) -> None:
        self._cache[key] = (time.monotonic(), content)
        while len(self._cache) > CACHE_MAX:
            self._cache.pop(next(iter(self._cache)))

    def _check_confirm(self, full: str, key: str, token: str | None) -> None:
        now = time.monotonic()
        self._pending = {t: v for t, v in self._pending.items() if v[2] > now}
        if token:
            entry = self._pending.get(token)
            if entry and entry[0] == full and entry[1] == key:
                del self._pending[token]  # single use
                return
            raise GatewayError("That confirmation is not valid for this call (wrong, used, or expired). "
                               "Call again without 'confirm' to get a new one.")
        token = secrets.token_urlsafe(6)
        self._pending[token] = (full, key, now + CONFIRM_TTL)
        raise GatewayError(
            f"{full} needs the user's approval before it runs. Tell the user exactly what it will do "
            f"(the tool and its arguments). If they agree, call call_tool again with the same arguments "
            f"and confirm=\"{token}\".")

    def _shape(self, content: list) -> list[ContentBlock]:
        text = _join_text(content)
        out: list[ContentBlock] = []
        if text or not content:
            out.append(TextContent(type="text", text=cap(text, self.settings.max_result_chars, self.store) if text else "(no output)"))
        out.extend(b for b in content if isinstance(b, ImageContent))
        for b in content:
            if not isinstance(b, (TextContent, ImageContent)):
                out.append(b)
        return out

    # -- info --------------------------------------------------------------
    def describe_backends(self) -> list[dict]:
        rows = []
        for b in self.backends.values():
            rows.append({
                "name": b.name, "transport": b.cfg.transport, "status": b.status(),
                "tools": len(b._tools) if b._tools is not None else None,
                "description": b.cfg.description,
                "source": b.cfg.source,
            })
        return sorted(rows, key=lambda r: r["name"])


def _join_text(content: list) -> str:
    return "\n".join(b.text for b in content if isinstance(b, TextContent))
