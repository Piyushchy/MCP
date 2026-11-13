import re
from pathlib import Path

import httpx
import pytest

from mcpgate import config as cfg
from mcpgate import site

ROOT = Path(__file__).resolve().parent.parent
SRC, PACKED = ROOT / "docs", ROOT / "mcpgate" / "data" / "site"


async def inner(scope, receive, send):
    body = f'inner:{scope["method"]}:{scope["path"]}'.encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": body})


@pytest.fixture
def client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=site.SiteFront(inner)), base_url="http://gate")


def test_the_packaged_site_is_the_same_as_the_one_github_pages_serves():
    """Run scripts/sync_site.py after changing docs/ if this fails."""
    names = [p.relative_to(PACKED).as_posix() for p in PACKED.rglob("*") if p.is_file()]
    assert "index.html" in names and "assets/site.css" in names
    for n in names:
        assert (PACKED / n).read_bytes() == (SRC / n).read_bytes(), n
    wanted = {p.relative_to(SRC).as_posix() for p in [SRC / "index.html", *(SRC / "assets").rglob("*")] if p.is_file() and p.name != "og.png"}
    assert set(names) == wanted


def test_the_page_runs_no_inline_code_and_loads_nothing_from_outside():
    html = (SRC / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "inline script would be blocked by the site's policy"
    assert " style=" not in html and "<style" not in html
    assert not re.search(r'(?:src|href)="https?://(?!github\.com|piyushchy\.is-a\.dev)', html)
    for ref in re.findall(r'(?:src|href)="(assets/[^"]+)"', html):
        assert (SRC / ref).is_file(), ref
    css = (SRC / "assets" / "site.css").read_text()
    assert "http" not in re.sub(r"/\*.*?\*/", "", css, flags=re.S)       # no remote fonts or images


async def test_root_and_assets_are_served_with_a_strict_policy(client):
    r = await client.get("/")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "mcpgate" in r.text and r.headers["x-content-type-options"] == "nosniff"
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe" not in csp
    for path, kind in [("/assets/site.css", "text/css"), ("/assets/site.js", "text/javascript"), ("/assets/theme.js", "text/javascript"),
                       ("/assets/favicon.svg", "image/svg+xml"), ("/assets/img/overview-light.webp", "image/webp"),
                       ("/assets/fonts/instrument-sans-latin-wght-normal.woff2", "font/woff2")]:
        a = await client.get(path)
        assert a.status_code == 200 and a.headers["content-type"].startswith(kind), path
        assert "content-security-policy" not in a.headers


async def test_head_has_no_body(client):
    r = await client.head("/")
    assert r.status_code == 200 and r.content == b"" and int(r.headers["content-length"]) > 1000


@pytest.mark.parametrize("path", ["/mcp", "/consent", "/token", "/register", "/authorize", "/.well-known/oauth-authorization-server",
                                  "/api/health", "/api/login", "/index.html", "/assets", "/assets/", "/assets/nope.css",
                                  "/assets/.hidden", "/ASSETS/site.css", "/assets//site.css"])
async def test_everything_else_goes_to_the_gateway_untouched(client, path):
    r = await client.get(path)
    assert r.text == f"inner:GET:{path}", path
    assert "content-security-policy" not in r.headers


@pytest.mark.parametrize("path", ["/assets/../index.html", "/assets/%2e%2e/index.html", "/assets/..%2fsite.css", "/assets/./site.css",
                                  "/assets/fonts/../site.css", "/assets\\site.css", "/assets/a\x00b", "/assets/.hidden", "/assets/fonts",
                                  "/assets/img/", "/", "/x"][:-2] + ["/x", "//assets/site.css"])
def test_no_trick_path_names_a_file(path):
    assert site.find(path) is None


def test_the_two_real_entry_points_do_name_files():
    assert site.find("/")[0] == "index.html" and site.find("/assets/site.css")[0] == "site.css"


async def test_only_get_and_head_are_answered_here(client):
    for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        r = await client.request(method, "/")
        assert r.text == f"inner:{method}:/", method


def test_the_site_setting_defaults_on_and_can_be_turned_off(tmp_path):
    assert cfg.Server().site is True
    p = tmp_path / "config.toml"
    s = cfg.Settings()
    s.server.site = False
    cfg.save(s, p)
    assert "site = false" in p.read_text() and cfg.load(p).server.site is False
    cfg.save(cfg.Settings(), p)
    assert "site" not in p.read_text().split("[server]")[-1] and cfg.load(p).server.site is True
