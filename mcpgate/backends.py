"""Connections to the real MCP servers the gateway routes to.

Each backend runs in its own task that owns the connection from start to stop
(the SDK's transports must be entered and left from the same task). Backends
start lazily on first use and are started again if they have died.
"""
from __future__ import annotations

import asyncio
import sys
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import timedelta

import anyio
import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError
from mcp.types import CONNECTION_CLOSED

from .config import Backend as BackendConfig
from .config import ConfigError, expand


_CLOSED = (anyio.ClosedResourceError, anyio.BrokenResourceError, anyio.EndOfStream)


class BackendError(RuntimeError):
    """A backend could not be started or did not answer."""


@dataclass
class ToolInfo:
    backend: str
    name: str
    description: str
    schema: dict
    read_only: bool = False
    destructive: bool = False

    @property
    def full(self) -> str:
        return f"{self.backend}.{self.name}"


class Backend:
    def __init__(self, cfg: BackendConfig, start_timeout: float = 30.0, secrets=None):
        self.cfg = cfg
        self.secrets = secrets
        self.start_timeout = start_timeout
        self.session: ClientSession | None = None
        self.error: str = ""
        self._task: asyncio.Task | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()
        self._tools: list[ToolInfo] | None = None
        self._tools_at = 0.0

    # -- lifecycle ---------------------------------------------------------
    @property
    def name(self) -> str:
        return self.cfg.name

    @property
    def connected(self) -> bool:
        return self.session is not None and self._task is not None and not self._task.done()

    def status(self) -> str:
        if not self.cfg.enabled:
            return "disabled"
        if self.connected:
            return "connected"
        return f"error: {self.error}" if self.error else "idle"

    async def ensure(self) -> ClientSession:
        """Return a live session, starting (or restarting) the backend if needed."""
        async with self._lock:
            if not self.connected:
                await self._start()
            assert self.session is not None
            return self.session

    async def _start(self) -> None:
        if not self.cfg.enabled:
            raise BackendError(f"{self.name} is disabled")
        self.error = ""
        self.session = None
        self._tools = None
        self._ready, self._stop = asyncio.Event(), asyncio.Event()
        self._task = asyncio.create_task(self._run(), name=f"backend-{self.name}")
        try:
            await asyncio.wait_for(self._ready.wait(), self.start_timeout)
        except asyncio.TimeoutError:
            self.error = f"did not start within {self.start_timeout:g}s"
            await self._shutdown_task()
            raise BackendError(f"{self.name}: {self.error}") from None
        if self.session is None:
            await self._shutdown_task()
            raise BackendError(f"{self.name}: {self.error or 'failed to start'}")

    async def _run(self) -> None:
        cfg = self.cfg
        lookup = self.secrets.get if self.secrets else None
        ex = lambda text: expand(text, lookup=lookup)  # noqa: E731
        try:
            async with AsyncExitStack() as stack:
                if cfg.transport == "stdio":
                    params = StdioServerParameters(
                        command=ex(cfg.command),
                        args=[ex(a) for a in cfg.args],
                        env={k: ex(v) for k, v in cfg.env.items()},
                        cwd=ex(cfg.cwd) if cfg.cwd else None,
                    )
                    read, write = await stack.enter_async_context(stdio_client(params, errlog=_errlog()))
                elif cfg.transport == "http":
                    client = await stack.enter_async_context(httpx.AsyncClient(
                        headers={k: ex(v) for k, v in cfg.headers.items()},
                        timeout=httpx.Timeout(30.0, read=300.0), follow_redirects=False))
                    read, write, _ = await stack.enter_async_context(
                        streamable_http_client(ex(cfg.url), http_client=client))
                else:
                    read, write = await stack.enter_async_context(sse_client(
                        ex(cfg.url), headers={k: ex(v) for k, v in cfg.headers.items()} or None))
                session = await stack.enter_async_context(ClientSession(read, write))
                try:
                    await asyncio.wait_for(session.initialize(), self.start_timeout)
                except asyncio.TimeoutError:
                    self.error = f"did not start within {self.start_timeout:g}s"
                    return
                self.session = session
                self._ready.set()
                await self._stop.wait()
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            self.error = f"did not start within {self.start_timeout:g}s"
        except ConfigError as e:
            self.error = self.error or self._clean(str(e))
        except Exception as e:  # noqa: BLE001 - any start/transport failure is reported, not raised
            # keep the first, clearer reason (e.g. "did not start"): closing a half-started process can raise again
            self.error = self.error or self._clean(_describe(e))
        finally:
            self.session = None
            self._ready.set()

    def _clean(self, text: str) -> str:
        return self.secrets.scrub(text) if self.secrets else text

    async def _shutdown_task(self) -> None:
        self._stop.set()
        task, self._task = self._task, None
        if task:
            try:
                await asyncio.wait_for(task, 5)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
                task.cancel()
        self.session = None

    async def stop(self) -> None:
        async with self._lock:
            await self._shutdown_task()

    # -- using it ----------------------------------------------------------
    async def tools(self, ttl: float = 300.0, refresh: bool = False) -> list[ToolInfo]:
        if not refresh and self._tools is not None and self.connected and time.monotonic() - self._tools_at < ttl:
            return self._tools
        session = await self.ensure()
        found: list[ToolInfo] = []
        cursor = None
        try:
            while True:
                page = await asyncio.wait_for(session.list_tools(cursor), self.cfg.timeout)
                for t in page.tools:
                    ann = t.annotations
                    found.append(ToolInfo(
                        backend=self.name, name=t.name, description=t.description or "",
                        schema=t.inputSchema or {"type": "object"},
                        read_only=bool(ann and ann.readOnlyHint),
                        destructive=bool(ann and ann.destructiveHint is True)))
                cursor = page.nextCursor
                if not cursor:
                    break
        except Exception as e:  # noqa: BLE001
            self.error = self._clean(_describe(e))
            await self.stop()
            raise BackendError(f"{self.name}: could not list tools ({self.error})") from None
        self._tools, self._tools_at = found, time.monotonic()
        return found

    async def call(self, tool: str, arguments: dict | None):
        """Call a tool. If the connection turns out to be closed, start the backend again once
        (nothing was sent on a closed stream, so retrying cannot repeat a side effect)."""
        for attempt in (1, 2):
            session = await self.ensure()
            try:
                return await session.call_tool(
                    tool, arguments or {}, read_timeout_seconds=timedelta(seconds=self.cfg.timeout))
            except McpError as e:
                if e.error.code == CONNECTION_CLOSED:  # the server went away mid-call
                    self.error = "connection closed"
                    await self.stop()
                raise BackendError(self._clean(f"{self.name}.{tool}: {e}")) from None
            except _CLOSED:
                await self.stop()
                if attempt == 2:
                    raise BackendError(f"{self.name}.{tool}: connection closed") from None
            except Exception as e:  # noqa: BLE001
                self.error = self._clean(_describe(e))
                await self.stop()
                raise BackendError(f"{self.name}.{tool}: connection problem ({self.error})") from None
        raise AssertionError("unreachable")


def _errlog():
    """Where a command backend's stderr goes: ours, but only if it is a real file (a captured
    stream has no file descriptor to hand to a child process). Never stdout: that is the protocol."""
    try:
        sys.stderr.fileno()
        return sys.stderr
    except (AttributeError, OSError, ValueError):
        return sys.__stderr__


def _describe(e: BaseException) -> str:
    if isinstance(e, BaseExceptionGroup) and e.exceptions:
        return _describe(e.exceptions[0])
    msg = str(e).strip()
    return f"{type(e).__name__}: {msg}" if msg else type(e).__name__
