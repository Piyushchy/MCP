"""Regenerates docs/screenshots/*.png (light and dark) from a seeded demo instance.

    python scripts/screenshots.py [PYTHON_WITH_MCPGATE]

Needs Playwright with Chromium. Uses a throw-away config, secrets and state folder; nothing of yours is touched."""
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "screenshots"
PY = sys.argv[1] if len(sys.argv) > 1 else sys.executable
PASS = "correct horse battery"
TOKEN = "t" * 40
SCHEMES = ("light", "dark")


def free():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(work: Path, config: str, token: bool, pre=None):
    admin, pub = free(), free()
    cfgdir = work / "mcpgate"
    cfgdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    (work / "state" / "mcpgate").mkdir(parents=True, mode=0o700, exist_ok=True)
    cfg = cfgdir / "config.toml"
    cfg.write_text(config.format(admin=admin, pub=pub, dir=cfgdir, repo=REPO, py=PY))
    cfg.chmod(0o600)
    env = {**os.environ, "MCPGATE_CONFIG": str(cfg), "XDG_STATE_HOME": str(work / "state"), "HOME": str(work)}
    env.pop("PYTHONPATH", None)
    if token:
        env["MCPGATE_TOKEN"] = TOKEN
    if pre:
        pre(env)
    proc = subprocess.Popen([PY, "-m", "mcpgate", "serve", "--service"], env=env, stderr=subprocess.PIPE, text=True)
    code = None
    for line in proc.stderr:
        m = re.search(r"[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}", line)
        if m:
            code = m.group(0)
            break
    for _ in range(200):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{admin}/api/health")
            break
        except Exception:
            time.sleep(0.1)
    return proc, admin, pub, code, env


def setup(page, admin, code):
    page.goto(f"http://127.0.0.1:{admin}/")
    page.get_by_label("Setup code").fill(code)
    page.get_by_label("New passphrase (12+ characters)").fill(PASS)
    page.get_by_label("Repeat passphrase").fill(PASS)
    page.get_by_role("button", name="Create admin passphrase").click()


def login(page, admin):
    page.goto(f"http://127.0.0.1:{admin}/")
    page.get_by_label("Passphrase").fill(PASS)
    page.get_by_role("button", name="Sign in").click()


def shot(page, selector, name, scheme):
    page.locator(selector).first.screenshot(path=str(OUT / f"{name}-{scheme}.png"))
    print("wrote", f"{name}-{scheme}.png")


with tempfile.TemporaryDirectory() as tmp, sync_playwright() as p:
    tmp = Path(tmp)
    browser = p.chromium.launch()

    # ---- run A: a fresh install: setup code, first-run guide, sign-in --------------------------------------------------
    a = tmp / "a"
    proc, admin, pub, code, env = start(a, "[server]\nadmin_port = {admin}\nport = {pub}\n", False)
    try:
        for scheme in SCHEMES:
            ctx = browser.new_context(viewport={"width": 760, "height": 900}, color_scheme=scheme)
            pg = ctx.new_page()
            pg.goto(f"http://127.0.0.1:{admin}/")
            if scheme == "light":
                pg.get_by_label("Setup code").wait_for()
                shot(pg, "main", "setup", scheme)
                setup(pg, admin, code)
            else:
                login(pg, admin)
            pg.get_by_role("heading", name="Set up mcpgate").wait_for()
            pg.get_by_role("button", name="GitHub").first.wait_for()
            shot(pg, "section[aria-labelledby=wiz]", "wizard", scheme)
            ctx.close()
            ctx = browser.new_context(viewport={"width": 760, "height": 700}, color_scheme=scheme)
            pg = ctx.new_page()
            pg.goto(f"http://127.0.0.1:{admin}/")
            pg.get_by_label("Passphrase").wait_for()
            shot(pg, "main", "signin", scheme)
            ctx.close()
    finally:
        proc.terminate()

    # ---- run B: a working install --------------------------------------------------------------------------------------
    b = tmp / "b"
    cfgtext = '''[gateway]
audit_log = "{dir}/audit.jsonl"
[server]
admin_port = {admin}
port = {pub}
public_url = "https://my-laptop.my-tailnet.ts.net"
oauth_enabled = true
wizard_done = true
[backends.demo]
transport = "stdio"
command = "{py}"
args = ["{repo}/tests/fixtures/demo_server.py"]
description = "Notes and small utilities"
confirm = ["create_*"]
deny = ["wipe"]
'''
    (b / "mcpgate").mkdir(parents=True, mode=0o700, exist_ok=True)
    now = time.time()
    rows = [("demo.echo", "ok", 12, {"text": "hello"}), ("demo.add", "ok", 9, {"a": 2, "b": 3}), ("demo.counter", "cached", 1, {}),
            ("demo.create_note", "ok", 41, {"title": "Shopping list"}), ("demo.whoami", "ok", 7, {}), ("demo.explode", "tool_error", 15, {}),
            ("demo.add", "ok", 8, {"a": 40, "b": 2})]
    with open(b / "mcpgate" / "audit.jsonl", "w") as f:
        for i, (tool, status, ms, args) in enumerate(rows):
            f.write(json.dumps({"ts": round(now - (len(rows) - i) * 190, 3), "tool": tool, "args": args, "status": status, "ms": ms}) + "\n")
        f.write(json.dumps({"ts": round(now - 60, 3), "event": "admin_backend_add", "name": "demo"}) + "\n")
    (b / "mcpgate" / "audit.jsonl").chmod(0o600)
    def seed_state(env):
        seed = f'''
from mcp.shared.auth import OAuthClientInformationFull
from mcpgate.authstore import AuthStore
from mcpgate.oauth import GatewayOAuth
import asyncio, pathlib
AuthStore().set_passphrase("oauth_passphrase", "a long sign-in passphrase")
p = GatewayOAuth("https://my-laptop.my-tailnet.ts.net", passphrase="a long sign-in passphrase", state_path=pathlib.Path("{b}/state/mcpgate/oauth.json"))
c = OAuthClientInformationFull(client_id="c1", client_name="Claude", redirect_uris=["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method="none")
asyncio.run(p.register_client(c))
p._issue("c1", [], None)
'''
        subprocess.run([PY, "-c", seed], env={**env, "PYTHONPATH": str(REPO)}, check=True)

    proc, admin, pub, code, env = start(b, cfgtext, True, seed_state)
    caller = f'''
import asyncio, httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
async def main():
    async with httpx.AsyncClient(headers={{"Authorization": "Bearer {TOKEN}"}}, timeout=120) as h:
        async with streamable_http_client("http://127.0.0.1:{pub}/mcp", http_client=h) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                await s.call_tool("call_tool", {{"name": "demo.create_note", "arguments": {{"title": "Pick up the parcel on Friday"}}}})
asyncio.run(main())
'''
    waiting = None
    try:
        for scheme in SCHEMES:
            ctx = browser.new_context(viewport={"width": 900, "height": 1000}, color_scheme=scheme)
            pg = ctx.new_page()
            if scheme == "light":
                setup(pg, admin, code)
                waiting = subprocess.Popen([PY, "-c", caller], env={**env, "PYTHONPATH": str(REPO)}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                login(pg, admin)
            def go(route, key):
                pg.evaluate(f"location.hash = '#/{route}'")
                pg.locator(f"section[aria-labelledby={key}]").wait_for(timeout=30000)
                pg.wait_for_timeout(600)
            pg.locator("nav[aria-label='Main menu']").wait_for(timeout=30000)
            go("overview", "ov")
            pg.wait_for_timeout(1500)
            shot(pg, "div.shell", "overview", scheme)
            go("approvals", "ap")
            pg.locator("article.pending").first.wait_for(timeout=40000)
            shot(pg, "section[aria-labelledby=ap]", "approvals", scheme)
            go("backends", "bk")
            pg.locator("article.backend").first.wait_for()
            shot(pg, "section[aria-labelledby=bk]", "backends", scheme)
            pg.get_by_role("button", name="Permissions").first.click()
            card = pg.locator("article.backend").first
            card.locator(".summary").wait_for(timeout=15000)
            pg.wait_for_timeout(500)
            shot(pg, "article.backend", "permissions", scheme)
            shot(pg, "section[aria-labelledby=add]", "add", scheme)
            go("remote", "rem")
            pg.locator("section[aria-labelledby=rem]").locator("p.note, h3").first.wait_for()
            shot(pg, "section[aria-labelledby=rem]", "remote", scheme)
            go("tokens", "tok")
            shot(pg, "section[aria-labelledby=tok]", "tokens", scheme)
            go("activity", "aud")
            pg.locator("section[aria-labelledby=aud] details.logrow").first.wait_for()
            pg.locator("section[aria-labelledby=aud] details.logrow").nth(3).locator("summary").click()
            shot(pg, "section[aria-labelledby=aud]", "activity", scheme)
            ctx.close()
    finally:
        if waiting:
            waiting.terminate()
        proc.terminate()
        browser.close()
