"""The project site, served on the public address next to the gateway.

``https://your-address/`` shows the site and ``https://your-address/mcp`` is the gateway, on one name and one tunnel,
with nothing between your computer and the browser. The files are part of this package (copied from ``docs/`` by
``scripts/sync_site.py``, and a test checks they match), so nothing is fetched from anywhere and nothing a visitor sends
is used for anything but picking one of those files. Only GET and HEAD for ``/`` and ``/assets/...`` are answered here;
every other request, including all of the gateway's paths, goes on to the gateway untouched. The admin page has no
part in this and is still only on the loopback address.
"""
from __future__ import annotations

from importlib import resources

ROOT = resources.files("mcpgate").joinpath("data", "site")
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".svg": "image/svg+xml", ".webp": "image/webp", ".png": "image/png", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8"}
# The site needs nothing from outside and runs no inline code, so the browser is told to allow nothing else.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'none'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
_cache: dict[str, bytes] = {}


def find(path: str) -> tuple[str, bytes] | None:
    """The (name, bytes) of the file a URL path means, or None. Only ``/`` and files under ``/assets/``."""
    if path == "/":
        parts = ["index.html"]
    elif path.startswith("/assets/"):
        parts = path[1:].split("/")
    else:
        return None
    if any(p in ("", ".", "..") or "\\" in p or "\x00" in p or p.startswith(".") for p in parts):
        return None
    node = ROOT.joinpath(*parts)
    try:
        if not node.is_file():
            return None
        key = "/".join(parts)
        if key not in _cache:
            _cache[key] = node.read_bytes()
        return parts[-1], _cache[key]
    except OSError:
        return None


class SiteFront:
    """ASGI wrapper: answers the site's own files, passes everything else to ``app``."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("GET", "HEAD"):
            return await self.app(scope, receive, send)
        hit = find(scope["path"])
        if hit is None:
            return await self.app(scope, receive, send)
        name, body = hit
        suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        ctype = TYPES.get(suffix)
        if ctype is None:
            return await self.app(scope, receive, send)
        page = suffix == ".html"
        headers = [(b"content-type", ctype.encode()), (b"content-length", str(len(body)).encode()),
                   (b"cache-control", b"no-cache" if page else b"public, max-age=3600"),
                   (b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"), (b"x-frame-options", b"DENY")]
        if page:
            headers.append((b"content-security-policy", CSP.encode()))
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": b"" if scope["method"] == "HEAD" else body})
