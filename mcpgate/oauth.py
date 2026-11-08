"""OAuth for remote use (what claude.ai needs to connect to the gateway over HTTPS).

A small single-owner authorization server built on the MCP SDK's OAuth endpoints. A client such as
claude.ai registers itself (Dynamic Client Registration), the browser is sent to ``/consent`` on the
gateway, and only someone who knows the owner's passphrase can approve it. Then the client gets
short-lived access tokens and rotating refresh tokens.

What is stored on disk (mode 600): registered clients and the SHA-256 *hashes* of issued tokens, so a
leaked state file cannot be used to call the gateway. Passphrase and static token come from the
environment and are never written.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from mcp.server.auth.provider import (AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
                                      RefreshToken, RegistrationError, TokenError, construct_redirect_uri)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

SCOPE = "mcp"
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
CODE_TTL = 300
PENDING_TTL = 600
MAX_CLIENTS = 200
MIN_PASSPHRASE = 12
DEFAULT_REDIRECT_HOSTS = ("claude.ai", "localhost", "127.0.0.1")
LOOPBACK = ("localhost", "127.0.0.1")


def default_state_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or "~/.local/state"
    return Path(base).expanduser() / "mcpgate" / "oauth.json"


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    """Clients and token hashes, kept in a JSON file. Re-read when another process (the CLI) changes it."""

    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {"clients": {}, "access": {}, "refresh": {}}
        self._mtime = None
        self._sync()

    def _sync(self) -> None:
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            if self._mtime is not None:  # deleted underneath us: everyone is signed out
                self.data = {"clients": {}, "access": {}, "refresh": {}}
                self._mtime = None
            return
        if mtime != self._mtime:
            try:
                loaded = json.loads(self.path.read_text())
                self.data = {k: loaded.get(k, {}) for k in ("clients", "access", "refresh")}
            except (OSError, ValueError):
                self.data = {"clients": {}, "access": {}, "refresh": {}}
            self._mtime = mtime

    def save(self) -> None:
        now = time.time()
        for kind in ("access", "refresh"):
            self.data[kind] = {h: v for h, v in self.data[kind].items() if v["exp"] > now}
        clients = self.data["clients"]
        if len(clients) > MAX_CLIENTS:  # claude.ai registers afresh on new connections; forget the idle oldest
            live = {v["client_id"] for k in ("access", "refresh") for v in self.data[k].values()}
            idle = sorted((c for c in clients if c not in live), key=lambda c: clients[c].get("client_id_issued_at") or 0)
            for c in idle[: len(clients) - MAX_CLIENTS]:
                del clients[c]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f)
        tmp.replace(self.path)
        self._mtime = self.path.stat().st_mtime_ns

    def clear(self) -> None:
        self.data = {"clients": {}, "access": {}, "refresh": {}}
        self.save()


class GatewayOAuth:
    """Implements the SDK's authorization-server provider for one owner."""

    def __init__(self, public_url: str, passphrase: str, state_path: Path | None = None,
                 redirect_hosts=DEFAULT_REDIRECT_HOSTS, static_token: str | None = None):
        if len(passphrase) < MIN_PASSPHRASE:
            raise ValueError(f"the passphrase must be at least {MIN_PASSPHRASE} characters")
        self.public_url = public_url.rstrip("/")
        self.passphrase = passphrase.encode()
        self.static_token = static_token.encode() if static_token else None
        self.redirect_hosts = {h.lower() for h in redirect_hosts}
        self.store = Store(state_path or default_state_path())
        self._codes: dict[str, AuthorizationCode] = {}
        self._pending: dict[str, tuple[OAuthClientInformationFull, AuthorizationParams, float]] = {}
        self._fails = 0
        self._locked_until = 0.0
        self._now = time.time  # replaced in tests

    # -- settings / routes ---------------------------------------------------
    @property
    def auth_settings(self) -> AuthSettings:
        return AuthSettings(
            issuer_url=self.public_url, resource_server_url=f"{self.public_url}/mcp",
            client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]),
            revocation_options=RevocationOptions(enabled=True),
            # one resource, and the owner's static token carries no audience, so there is nothing to compare
            validate_token_resource=False)

    def install(self, app) -> None:
        app.custom_route("/consent", methods=["GET", "POST"])(self.consent)

    # -- clients -------------------------------------------------------------
    async def get_client(self, client_id: str):
        self.store._sync()
        raw = self.store.data["clients"].get(client_id)
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            u = urlparse(str(uri))
            host = (u.hostname or "").lower()
            ok_scheme = u.scheme == "https" or (u.scheme == "http" and host in LOOPBACK)
            if not ok_scheme or host not in self.redirect_hosts or u.fragment:
                raise RegistrationError("invalid_redirect_uri", f"redirect host {host or u.netloc!r} is not allowed by this gateway")
        self.store._sync()
        self.store.data["clients"][client_info.client_id] = json.loads(client_info.model_dump_json())
        self.store.save()

    # -- authorize: hand the browser to our consent page -----------------------
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        now = self._now()
        self._pending = {k: v for k, v in self._pending.items() if v[2] > now}
        if len(self._pending) >= 200:
            raise AuthorizeError("temporarily_unavailable", "too many pending approvals")
        req = secrets.token_urlsafe(24)
        self._pending[req] = (client, params, now + PENDING_TTL)
        return f"{self.public_url}/consent?req={req}"

    async def consent(self, request: Request) -> Response:
        now = self._now()
        if request.method == "GET":
            req = request.query_params.get("req", "")
            return self._page(req, "") if self._live(req, now) else self._page(None, "This approval link is not valid or has expired. Start again from the app.", 400)
        body = parse_qs((await request.body())[:4096].decode("utf-8", "replace"))
        req = (body.get("req") or [""])[0]
        entry = self._live(req, now)
        if not entry:
            return self._page(None, "This approval link is not valid or has expired. Start again from the app.", 400)
        client, params, _ = entry
        if (body.get("decision") or [""])[0] == "deny":
            del self._pending[req]
            return self._redirect(str(params.redirect_uri), error="access_denied", state=params.state)
        if now < self._locked_until:
            return self._page(req, f"Too many wrong attempts. Try again in {int(self._locked_until - now) + 1} seconds.", 429)
        given = (body.get("passphrase") or [""])[0].encode()
        if not hmac.compare_digest(hashlib.sha256(given).digest(), hashlib.sha256(self.passphrase).digest()):
            self._fails += 1
            if self._fails >= 5:  # lock for 1, 2, 4... minutes (max 15) so guessing is impractical
                self._locked_until = now + min(900, 60 * 2 ** (self._fails - 5))
                return self._page(req, "Too many wrong attempts. Locked for a while.", 429)
            return self._page(req, "Wrong passphrase.", 401)
        self._fails = 0
        del self._pending[req]
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthorizationCode(
            code=code, scopes=[SCOPE], expires_at=now + CODE_TTL, client_id=client.client_id,
            code_challenge=params.code_challenge, redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource, subject="owner")
        return self._redirect(str(params.redirect_uri), code=code, state=params.state)

    def _live(self, req: str, now: float):
        entry = self._pending.get(req)
        if entry and entry[2] > now:
            return entry
        self._pending.pop(req, None)
        return None

    @staticmethod
    def _redirect(base: str, **params) -> Response:
        return RedirectResponse(construct_redirect_uri(base, **params), status_code=303,
                                headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    def _page(self, req: str | None, message: str, status: int = 200) -> HTMLResponse:
        who = ""
        form = ""
        if req:
            client, params, _ = self._pending[req]
            host = urlparse(str(params.redirect_uri)).netloc
            name = html.escape(client.client_name or "An app")
            who = (f"<p><b>{name}</b> wants to use your mcpgate tools.</p>"
                   f"<p class=small>It will be sent back to <b>{html.escape(host)}</b>. "
                   f"Only approve if you just started this connection yourself.</p>")
            form = (f'<form method="post"><input type="hidden" name="req" value="{html.escape(req)}">'
                    f'<label>Passphrase<input type="password" name="passphrase" autocomplete="current-password" autofocus required></label>'
                    f'<div class="row"><button name="decision" value="approve">Approve</button>'
                    f'<button class="deny" name="decision" value="deny" formnovalidate>Deny</button></div></form>')
        msg = f'<p class="msg">{html.escape(message)}</p>' if message else ""
        page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark">
<title>mcpgate: approve access</title><style>
:root{{--bg:#fff;--ink:#16181d;--mute:#5b6270;--line:#d6dae1;--accent:#0e6b5a;--bad:#b3261e}}
@media(prefers-color-scheme:dark){{:root{{--bg:#14161a;--ink:#e8eaee;--mute:#9aa3b2;--line:#2c313a;--accent:#4cc3a6;--bad:#f2b8b5}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh}}
main{{width:min(26rem,calc(100vw - 2rem));padding:1.5rem 0}}h1{{font-size:1.25rem;margin:0 0 1rem}}
.small{{color:var(--mute);font-size:.9rem}}.msg{{color:var(--bad)}}label{{display:block;margin:1rem 0 .25rem}}
input[type=password]{{display:block;width:100%;box-sizing:border-box;margin-top:.25rem;padding:.6rem;font:inherit;color:inherit;background:transparent;border:1px solid var(--line);border-radius:6px}}
.row{{display:flex;gap:.5rem;margin-top:1rem}}button{{flex:1;padding:.6rem;font:inherit;border-radius:6px;border:1px solid var(--accent);background:var(--accent);color:var(--bg);cursor:pointer}}
button.deny{{background:transparent;color:var(--ink);border-color:var(--line)}}
</style></head><body><main><h1>mcpgate</h1>{who}{msg}{form}</main></body></html>"""
        return HTMLResponse(page, status_code=status, headers={
            "Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"})

    # -- codes and tokens -------------------------------------------------------
    async def load_authorization_code(self, client, authorization_code: str):
        code = self._codes.get(authorization_code)
        if code and code.client_id == client.client_id and code.expires_at > self._now():
            return code
        self._codes.pop(authorization_code, None)
        return None

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        if self._codes.pop(authorization_code.code, None) is None:  # single use
            raise TokenError("invalid_grant", "authorization code already used")
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource)

    def _issue(self, client_id: str, scopes: list[str], resource: str | None) -> OAuthToken:
        self.store._sync()
        now = self._now()
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        grant = secrets.token_hex(8)
        common = {"client_id": client_id, "scopes": scopes or [SCOPE], "resource": resource, "grant": grant}
        self.store.data["access"][_h(access)] = {**common, "exp": int(now + ACCESS_TTL)}
        self.store.data["refresh"][_h(refresh)] = {**common, "exp": int(now + REFRESH_TTL)}
        self.store.save()
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL,
                          scope=" ".join(scopes or [SCOPE]), refresh_token=refresh)

    async def load_refresh_token(self, client, refresh_token: str):
        self.store._sync()
        rec = self.store.data["refresh"].get(_h(refresh_token))
        if rec and rec["client_id"] == client.client_id and rec["exp"] > self._now():
            return RefreshToken(token=refresh_token, client_id=rec["client_id"], scopes=rec["scopes"],
                                expires_at=rec["exp"], resource=rec.get("resource"), subject="owner")
        return None

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        self.store._sync()
        old = self.store.data["refresh"].pop(_h(refresh_token.token), None)  # rotate: the old one dies now
        if old is None:
            raise TokenError("invalid_grant", "refresh token already used or revoked")
        for h in [h for h, v in self.store.data["access"].items() if v["grant"] == old["grant"]]:
            del self.store.data["access"][h]
        return self._issue(client.client_id, scopes or old["scopes"], old.get("resource"))

    async def load_access_token(self, token: str):
        if self.static_token and hmac.compare_digest(token.encode(), self.static_token):
            return AccessToken(token=token, client_id="static-token", scopes=[SCOPE], expires_at=None, subject="owner")
        self.store._sync()
        rec = self.store.data["access"].get(_h(token))
        if rec and rec["exp"] > self._now():
            return AccessToken(token=token, client_id=rec["client_id"], scopes=rec["scopes"], expires_at=rec["exp"],
                               resource=rec.get("resource"), subject="owner")
        return None

    async def revoke_token(self, token) -> None:
        self.store._sync()
        h = _h(token.token)
        rec = self.store.data["access"].get(h) or self.store.data["refresh"].get(h)
        if rec:  # a revoked grant takes its sibling tokens with it
            for kind in ("access", "refresh"):
                self.store.data[kind] = {k: v for k, v in self.store.data[kind].items() if v["grant"] != rec["grant"]}
            self.store.save()
