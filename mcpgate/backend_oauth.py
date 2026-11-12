"""Signing in to remote backends that ask for an account instead of a token.

mcpgate is the OAuth *client* here (the opposite of oauth.py, where it is the server for claude.ai). The owner
presses "Sign in" on the admin page; mcpgate discovers the server's sign-in endpoints, registers itself, and gives
the owner a link to the server's own login page. The server sends the browser back to the admin page's loopback
callback with a one-time code, which mcpgate exchanges (PKCE) for tokens. Tokens are stored in a private file,
never returned by any endpoint, and refreshed automatically."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl

FLOW_TTL = 300.0


class SignInRequired(Exception):
    """The backend wants the owner to sign in (or sign in again)."""

    def __init__(self, name: str = ""):
        super().__init__(f"{name + ': ' if name else ''}sign-in needed. Open the admin page, choose Backends, and press Sign in.")


class Store:
    """backend name -> {"tokens": ..., "client": ...}, in one file readable only by this user."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def get(self, name: str) -> dict:
        with self._lock:
            return dict(self._read().get(name, {}))

    def update(self, name: str, **fields) -> None:
        with self._lock:
            data = self._read()
            cur = data.setdefault(name, {})
            for k, v in fields.items():
                if v is None:
                    cur.pop(k, None)
                else:
                    cur[k] = v
            if not cur:
                data.pop(name, None)
            self._write(data)

    def forget(self, name: str) -> bool:
        with self._lock:
            data = self._read()
            had = data.pop(name, None) is not None
            if had:
                self._write(data)
            return had

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".backend_oauth.")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


class _Storage:
    def __init__(self, store: Store, name: str):
        self.store, self.name = store, name

    async def get_tokens(self):
        d = self.store.get(self.name).get("tokens")
        return OAuthToken.model_validate(d) if d else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.store.update(self.name, tokens=tokens.model_dump(mode="json", exclude_none=True))

    async def get_client_info(self):
        d = self.store.get(self.name).get("client")
        return OAuthClientInformationFull.model_validate(d) if d else None

    async def set_client_info(self, info: OAuthClientInformationFull) -> None:
        self.store.update(self.name, client=info.model_dump(mode="json", exclude_none=True))


@dataclass
class Flow:
    name: str
    started: float = field(default_factory=time.monotonic)
    url: asyncio.Future = field(default_factory=lambda: asyncio.get_running_loop().create_future())
    code: asyncio.Future = field(default_factory=lambda: asyncio.get_running_loop().create_future())
    task: asyncio.Task | None = None
    state: str = ""
    error: str = ""


def _safe_authorize_url(url: str) -> str:
    u = urlsplit(url)
    if u.scheme == "https" or (u.scheme == "http" and (u.hostname or "") in ("127.0.0.1", "localhost", "::1")):
        return url
    raise SignInRequired("the server sent a sign-in address that is not https")


class BackendOAuth:
    def __init__(self, path: Path, redirect_uri):
        self.store = Store(path)
        self._redirect_uri = redirect_uri          # a callable: the admin port can change
        self.flows: dict[str, Flow] = {}
        self.by_state: dict[str, Flow] = {}

    def redirect_uri(self) -> str:
        return self._redirect_uri()

    def _metadata(self) -> OAuthClientMetadata:
        return OAuthClientMetadata(client_name="mcpgate", redirect_uris=[AnyUrl(self.redirect_uri())],
                                   grant_types=["authorization_code", "refresh_token"], response_types=["code"],
                                   token_endpoint_auth_method="none")

    def signed_in(self, name: str) -> bool:
        return bool(self.store.get(name).get("tokens"))

    def pending(self, name: str) -> bool:
        f = self.flows.get(name)
        return bool(f and f.task and not f.task.done() and time.monotonic() - f.started < FLOW_TTL)

    def provider(self, name: str, url: str) -> OAuthClientProvider:
        """For ordinary use: attaches and refreshes tokens, never starts a login by itself."""
        async def redirect(_u: str) -> None:
            raise SignInRequired(name)

        async def callback():
            raise SignInRequired(name)
        return OAuthClientProvider(url, self._metadata(), _Storage(self.store, name), redirect, callback, timeout=30.0)

    def forget(self, name: str) -> bool:
        self.cancel(name)
        return self.store.forget(name)

    def cancel(self, name: str) -> None:
        f = self.flows.pop(name, None)
        if f:
            self.by_state.pop(f.state, None)
            if f.task and not f.task.done():
                f.task.cancel()

    async def begin(self, name: str, transport: str, url: str, headers: dict[str, str], on_done=None) -> str | None:
        """Start a login. Returns the address of the server's login page, or None if no sign-in was asked for."""
        self.cancel(name)
        flow = Flow(name)
        self.flows[name] = flow

        async def redirect(u: str) -> None:
            u = _safe_authorize_url(u)
            state = (parse_qs(urlsplit(u).query).get("state") or [""])[0]
            if not state:
                raise SignInRequired("the server sent no sign-in state")
            flow.state = state
            self.by_state[state] = flow
            if not flow.url.done():
                flow.url.set_result(u)

        async def callback():
            return await asyncio.wait_for(flow.code, FLOW_TTL)

        provider = OAuthClientProvider(url, self._metadata(), _Storage(self.store, name), redirect, callback, timeout=FLOW_TTL)

        async def run() -> None:
            try:
                async with httpx.AsyncClient(auth=provider, headers=headers, timeout=httpx.Timeout(30.0, read=FLOW_TTL),
                                             follow_redirects=False) as client:
                    if transport == "http":
                        cm = streamable_http_client(url, http_client=client)
                    else:
                        cm = sse_client(url, headers=headers or None, auth=provider)
                    async with cm as streams:
                        async with ClientSession(streams[0], streams[1]) as session:
                            await asyncio.wait_for(session.initialize(), FLOW_TTL)
            except asyncio.CancelledError:
                raise
            except BaseException as e:  # noqa: BLE001 - reported to the owner, never raised into the server
                while isinstance(e, BaseExceptionGroup) and e.exceptions:
                    e = e.exceptions[0]
                flow.error = str(e) or type(e).__name__
                if not flow.url.done():
                    flow.url.set_exception(SignInRequired(flow.error))
                    flow.url.exception()
            finally:
                self.by_state.pop(flow.state, None)
                if self.flows.get(name) is flow and not flow.error:
                    self.flows.pop(name, None)
            if on_done and not flow.error:
                await on_done()

        flow.task = asyncio.create_task(run(), name=f"signin-{name}")
        done, _ = await asyncio.wait({flow.url, flow.task}, timeout=30, return_when=asyncio.FIRST_COMPLETED)
        if flow.url.done():
            return flow.url.result()
        if flow.task.done():
            if flow.error:
                raise SignInRequired(flow.error)
            return None                                   # the server let us in without asking
        self.cancel(name)
        raise SignInRequired("the server did not answer in time")

    def finish(self, state: str, code: str | None, error: str | None) -> str | None:
        """The browser came back to the callback. Returns the backend's name if this belongs to a login we started."""
        flow = self.by_state.get(state or "")
        if not flow or flow.code.done() or time.monotonic() - flow.started > FLOW_TTL:
            return None
        if code and not error:
            flow.code.set_result((code, state))
        else:
            flow.error = error or "the server refused the sign-in"
            flow.code.set_exception(SignInRequired(flow.error))
            flow.code.exception()
        return flow.name
