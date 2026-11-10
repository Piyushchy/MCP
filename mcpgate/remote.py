"""Remote access, as the admin page needs it: validating the settings, telling what needs a restart, checking the
public address, and the copy-ready setup instructions. The check only ever contacts the saved public address."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
from urllib.parse import urlparse

import httpx

from .config import HOST_RE, ConfigError, Settings, check_public_url

CHECK_TIMEOUT = 8.0
MAX_BODY = 64 * 1024
TAILSCALE_V4 = ipaddress.ip_network("100.64.0.0/10")        # tailnet addresses: a machine's own MagicDNS name resolves here
TAILSCALE_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")


# -- settings ---------------------------------------------------------------------------------
def validate_settings(d: dict, admin_port: int) -> dict:
    """Clean values for [server], or raise ConfigError with a plain message."""
    out: dict = {}
    if "public_url" in d:
        url = d["public_url"]
        if not isinstance(url, str):
            raise ConfigError("the public address must be text")
        out["public_url"] = check_public_url(url) if url.strip() else ""
        if out["public_url"].startswith("http://"):
            raise ConfigError("the public address must be https:// (claude.ai will not connect to plain http)")
    if "port" in d:
        port = d["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ConfigError("the local port must be a number between 1024 and 65535")
        if port == admin_port:
            raise ConfigError("the gateway port must differ from the admin port")
        out["port"] = port
    if "allow_hosts" in d:
        hosts = d["allow_hosts"]
        if not isinstance(hosts, list) or len(hosts) > 20 or not all(isinstance(h, str) and HOST_RE.match(h) and len(h) <= 253 for h in hosts):
            raise ConfigError("allowed hosts must be a list of host names (at most 20), without https:// or a path")
        out["allow_hosts"] = list(dict.fromkeys(h.lower() for h in hosts))
    if "oauth_enabled" in d:
        if not isinstance(d["oauth_enabled"], bool):
            raise ConfigError("oauth_enabled must be true or false")
        out["oauth_enabled"] = d["oauth_enabled"]
    return out


def wanted(settings: Settings, auth, env_token: bool = False, env_pass: bool = False) -> dict:
    """What the service would run with, given the saved settings. Compared with what it started with."""
    srv = settings.server
    has_pass = env_pass or auth.has("oauth_passphrase")
    oauth = bool(srv.oauth_enabled and srv.public_url and has_pass)
    static = bool(env_token or (srv.static_token_enabled and auth.has("static_token")))
    return {"listener": bool(oauth or static), "oauth": oauth, "static": static,
            "public_url": srv.public_url.rstrip("/") if oauth else "", "port": srv.port, "hosts": sorted(srv.allow_hosts)}


def supervised() -> bool:
    """True when something will start the service again after it exits (systemd sets INVOCATION_ID)."""
    return bool(os.environ.get("INVOCATION_ID") or os.environ.get("MCPGATE_SUPERVISED"))


class Restarter:
    """Asks the running service to stop so its supervisor starts it again with the saved settings."""
    EXIT_CODE = 75

    def __init__(self):
        self.requested = False
        self._stop = None

    def attach(self, stop) -> None:
        self._stop = stop

    def trigger(self) -> None:
        self.requested = True
        if self._stop:
            self._stop()


# -- the public address check ----------------------------------------------------------------------
def _address_ok(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if a.is_multicast or a.is_unspecified or a.is_loopback or a.is_link_local or a.is_reserved:
        return False
    return a.is_global or a in TAILSCALE_V4 or a in TAILSCALE_V6


def address_problem(host: str, resolve=None) -> str | None:
    """Why this host must not be contacted, or None. The public address has to be a real public name."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return "The public address must be a host name, not an IP address."
    except ValueError:
        pass
    try:
        infos = (resolve or socket.getaddrinfo)(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return None   # does not resolve: reported as unreachable by the request itself
    bad = sorted({i[4][0] for i in infos if not _address_ok(i[4][0])})
    if bad:
        return f"{host} points at {bad[0]}, which is a private or local address. The public address must be reachable from the internet."
    return None


def _result(name: str, ok, detail: str, advice: str = "") -> dict:
    return {"name": name, "ok": ok, "detail": detail, "advice": advice}


async def _get(client: httpx.AsyncClient, url: str, **kw) -> tuple[httpx.Response, bytes]:
    async with client.stream("GET", url, **kw) as r:
        body = b""
        async for chunk in r.aiter_bytes():
            body += chunk
            if len(body) >= MAX_BODY:
                break
        return r, body[:MAX_BODY]


def _explain(e: Exception) -> tuple[str, str]:
    text = str(e).lower()
    if isinstance(e, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout)):
        return "The address did not answer within a few seconds.", "Check that the tunnel is running and the gateway is started (mcpgate serve --service)."
    if "certificate" in text or "ssl" in text or "tls" in text:
        return "The secure connection failed (certificate problem).", "Use the exact https address your tunnel gives you; Tailscale and Cloudflare provide the certificate for you."
    if isinstance(e, httpx.ConnectError):
        return "Could not connect to that address.", "Check the address for typos, and that your tunnel is running (see the instructions below)."
    return "The request failed.", "Check the address and the tunnel."


async def check(url: str, *, transport=None, resolve=None) -> list[dict]:
    """Fetch the discovery document and the unauthenticated /mcp response from the saved public address, nothing else.
    No redirects are followed, each request is short, and only the status and a few fields are reported."""
    url = check_public_url(url)
    host = urlparse(url).hostname or ""
    loop = asyncio.get_running_loop()
    problem = await loop.run_in_executor(None, address_problem, host, resolve)
    if problem:
        return [_result("Address", False, problem, "Use the https address of your tunnel (for example your Tailscale Funnel name).")]
    results = [_result("Address", True, f"{url} is a public address.")]
    async with httpx.AsyncClient(timeout=CHECK_TIMEOUT, follow_redirects=False, transport=transport,
                                 headers={"user-agent": "mcpgate-connection-check"}) as client:
        # 1. the OAuth discovery document claude.ai reads first
        try:
            r, body = await _get(client, url + "/.well-known/oauth-authorization-server")
        except httpx.HTTPError as e:
            detail, advice = _explain(e)
            return results + [_result("Discovery", False, detail, advice)]
        server = (r.headers.get("server") or "").lower()
        if 300 <= r.status_code < 400:
            results.append(_result("Discovery", False, f"The address answers with a redirect (HTTP {r.status_code}). Redirects are not followed.",
                                   "claude.ai needs the address to answer directly. Use the final address in the saved public address."))
        elif r.status_code in (403, 429, 503) and ("cloudflare" in server or "cf-ray" in r.headers):
            results.append(_result("Discovery", False, f"Cloudflare blocked the request (HTTP {r.status_code}).",
                                   "Turn off bot protection, captcha, Access and WAF challenges for this host: claude.ai connects from a server, not a browser."))
        elif r.status_code == 404:
            results.append(_result("Discovery", False, "A web server answers, but it is not this gateway with sign-in turned on.",
                                   "Check that the tunnel points at the gateway port, that remote sign-in is on, and (Tailscale) that this port is not used by another Funnel."))
        elif r.status_code != 200:
            results.append(_result("Discovery", False, f"Unexpected answer (HTTP {r.status_code}).", "Check that the tunnel points at the gateway port."))
        else:
            try:
                doc = json.loads(body)
                issuer = str(doc.get("issuer", "")).rstrip("/")
                missing = [k for k in ("authorization_endpoint", "token_endpoint", "registration_endpoint") if k not in doc]
            except (ValueError, AttributeError):
                results.append(_result("Discovery", False, "The address answers, but not with the gateway's sign-in information.", "Check that the tunnel points at the gateway port."))
            else:
                if issuer != url:
                    results.append(_result("Discovery", False, f"The gateway believes its address is {issuer or 'unknown'}, but you reached it as {url}.",
                                           "Save the public address exactly as claude.ai will use it, then apply and restart."))
                elif missing:
                    results.append(_result("Discovery", False, "The sign-in information is incomplete: " + ", ".join(missing), "Restart the gateway and check again."))
                else:
                    results.append(_result("Discovery", True, "claude.ai can find the sign-in endpoints."))
        # 2. the MCP endpoint must refuse an unauthenticated request, and say how to sign in
        try:
            r, _ = await _get(client, url + "/mcp", headers={"accept": "application/json, text/event-stream"})
        except httpx.HTTPError as e:
            detail, advice = _explain(e)
            return results + [_result("MCP endpoint", False, detail, advice)]
        if r.status_code == 401:
            if "bearer" in (r.headers.get("www-authenticate") or "").lower():
                results.append(_result("MCP endpoint", True, "Refuses requests without a login, as it should."))
            else:
                results.append(_result("MCP endpoint", None, "Refuses requests without a login, but does not say how to sign in.", "claude.ai may not start the sign-in. Restart the gateway and check again."))
        elif r.status_code == 200 or r.status_code == 202:
            results.append(_result("MCP endpoint", False, "Answers without any login. Anyone who knows the address could use your tools.",
                                   "Turn on remote sign-in (passphrase) or a token, then apply and restart."))
        elif 300 <= r.status_code < 400:
            results.append(_result("MCP endpoint", False, f"Redirects (HTTP {r.status_code}); redirects are not followed.", "Use the final address."))
        else:
            results.append(_result("MCP endpoint", False, f"Unexpected answer (HTTP {r.status_code}).", "Check that the address ends where the gateway starts (no path)."))
    return results


# -- copy-ready instructions ---------------------------------------------------------------------------
def instructions(public_url: str, port: int) -> dict:
    host = urlparse(public_url).hostname if public_url else ""
    pub = urlparse(public_url).port if public_url else None
    shown = public_url or "https://<your-machine>.<your-tailnet>.ts.net"
    connector = shown.rstrip("/") + "/mcp"
    second = pub in (8443, 10000)
    funnel_port = pub if second else 443
    tail_cmd = f"sudo tailscale funnel --bg {port}" if not second else f"sudo tailscale funnel --bg --https={funnel_port} {port}"
    return {
        "connector_url": connector,
        "tailscale": {
            "title": "Tailscale Funnel",
            "intro": ("Funnel publishes a port of this computer at a public https address, with the certificate handled for you. "
                      "It offers three public ports: 443, 8443 and 10000."),
            "steps": [
                "Run this on the computer that runs mcpgate:",
                "If port 443 is already used by something else (another Funnel), publish the gateway on 8443 instead, and put :8443 at the end of the public address above.",
                "Run `tailscale funnel status` to see what is published.",
            ],
            "commands": [tail_cmd] + ([] if second else [f"sudo tailscale funnel --bg --https=8443 {port}   # only if 443 is taken"]),
        },
        "cloudflare": {
            "title": "Cloudflare Tunnel",
            "intro": ("A tunnel publishes this computer under your own domain. Do not put a captcha, bot protection, Cloudflare Access or WAF "
                      "challenge in front of it: claude.ai connects server to server, and any challenge makes the connection fail."),
            "steps": ["Quick test (a temporary address that changes each time):", "For a permanent address, create a named tunnel in the Cloudflare dashboard, give it a public hostname, and point the service at:"],
            "commands": [f"cloudflared tunnel --url http://127.0.0.1:{port}", f"http://127.0.0.1:{port}"],
        },
        "claude": [
            "In claude.ai open Settings, then Connectors, then Add custom connector.",
            f"Give it a name and paste the connector address: {connector}",
            "Click Connect. claude.ai opens the gateway's approval page.",
            "Enter your approval passphrase (the one you set on this page) and approve.",
        ],
        "host": host or "",
    }
