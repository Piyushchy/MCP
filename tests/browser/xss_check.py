"""Real-browser XSS check. Run by tests/test_security_browser.py with an interpreter that has Playwright.

    python xss_check.py WORKDIR PYTHON_WITH_MCPGATE        prints one JSON object

A hostile MCP server, a hostile OAuth app name, hostile audit lines and a hostile pending approval are put in front of
the real admin page; the check is that nothing runs and everything shows up as plain text."""
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

WORK, PY = Path(sys.argv[1]), sys.argv[2]
REPO = Path(__file__).resolve().parent.parent.parent
EVIL = "<img src=x onerror=window.__pwned=1><script>window.__pwned=2</script>\"'`"
PASS = "correct horse battery"
TOKEN = "t" * 40


def free():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


admin, pub = free(), free()
cfgdir = WORK / "mcpgate"
cfgdir.mkdir(mode=0o700)
(WORK / "state" / "mcpgate").mkdir(parents=True, mode=0o700)
cfg = cfgdir / "config.toml"
cfg.write_text(f'''[gateway]
audit_log = "{cfgdir}/audit.jsonl"
[server]
admin_port = {admin}
port = {pub}
[backends.evil]
transport = "stdio"
command = "{PY}"
args = ["{REPO}/tests/fixtures/evil_server.py"]
description = {json.dumps(EVIL)}
confirm = ["create_*"]
''')
cfg.chmod(0o600)
now = time.time()
with open(cfgdir / "audit.jsonl", "w") as f:
    f.write(json.dumps({"ts": now, "tool": "evil." + EVIL, "args": {EVIL: EVIL}, "status": EVIL, "ms": 1}) + "\n")
    f.write(json.dumps({"ts": now, "event": "admin_" + EVIL, "name": EVIL}) + "\n")
(cfgdir / "audit.jsonl").chmod(0o600)

env = {**os.environ, "MCPGATE_CONFIG": str(cfg), "XDG_STATE_HOME": str(WORK / "state"), "HOME": str(WORK), "MCPGATE_TOKEN": TOKEN}
env.pop("PYTHONPATH", None)
seed = f'''
from mcp.shared.auth import OAuthClientInformationFull
from mcpgate.oauth import GatewayOAuth
import asyncio
p = GatewayOAuth("https://box.example.com", passphrase="{PASS}", state_path=__import__("pathlib").Path("{WORK}/state/mcpgate/oauth.json"))
c = OAuthClientInformationFull(client_id="c1", client_name={EVIL!r}, redirect_uris=["https://claude.ai/cb"], token_endpoint_auth_method="none")
asyncio.run(p.register_client(c))
p._issue("c1", [], None)
'''
subprocess.run([PY, "-c", seed], env={**env, "PYTHONPATH": str(REPO)}, check=True)

caller = f'''
import asyncio, httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
async def main():
    async with httpx.AsyncClient(headers={{"Authorization": "Bearer {TOKEN}"}}, timeout=60) as h:
        async with streamable_http_client("http://127.0.0.1:{pub}/mcp", http_client=h) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                await s.call_tool("call_tool", {{"name": "evil.create_note", "arguments": {{"title": {EVIL!r}}}}})
asyncio.run(main())
'''
proc = subprocess.Popen([PY, "-m", "mcpgate", "serve", "--service"], env=env, stderr=subprocess.PIPE, text=True)
calls = []
out = {}
try:
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
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1100, "height": 1600})
        dialogs, problems = [], []
        pg.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        pg.on("pageerror", lambda e: problems.append(str(e)))
        pg.goto(f"http://127.0.0.1:{admin}/")
        pg.get_by_label("Setup code").fill(code)
        pg.get_by_label("New passphrase (12+ characters)").fill(PASS)
        pg.get_by_label("Repeat passphrase").fill(PASS)
        pg.get_by_role("button", name="Create admin passphrase").click()
        # the first-run guide opens by itself only with no backend; there is one, so the full page shows
        pg.get_by_role("heading", name="Backends").wait_for(timeout=30000)
        calls.append(subprocess.Popen([PY, "-c", caller], env={**env, "PYTHONPATH": str(REPO)}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        pg.locator("article.pending").first.wait_for(timeout=40000)
        pg.get_by_role("button", name="Permissions").first.click()
        pg.wait_for_timeout(1500)
        pg.locator("section[aria-labelledby=rem]").locator("details summary").click()
        pg.wait_for_timeout(300)
        for sel in ("section[aria-labelledby=aud]",):
            pg.locator(sel).locator("details.logrow summary").first.click()
        pg.wait_for_timeout(500)
        text = pg.locator("body").inner_text()
        out = {
            "pwned": pg.evaluate("window.__pwned === undefined ? null : window.__pwned"),
            "dialogs": dialogs,
            "page_errors": problems,
            "injected_img": pg.locator("img").count(),
            "scripts": pg.locator("script").count(),
            "payload_visible_as_text": text.count("onerror=window.__pwned=1"),
            "shown_in": {
                "backend_description": pg.locator("section[aria-labelledby=bk]").inner_text().count("onerror=window.__pwned=1") if pg.locator("section[aria-labelledby=bk]").count() else -1,
                "approval": pg.locator("article.pending").first.inner_text().count("onerror=window.__pwned=1"),
                "app_name": pg.locator("section[aria-labelledby=rem]").inner_text().count("onerror=window.__pwned=1"),
                "audit": pg.locator("section[aria-labelledby=aud]").inner_text().count("onerror=window.__pwned=1"),
            },
            "html_has_raw_payload": "<img src=x onerror" in pg.content().replace("&lt;", "<").split("<body")[0],
        }
        # the live DOM must contain the payload only inside text nodes
        out["dom_img_with_src_x"] = pg.evaluate("document.querySelectorAll('img[src=x], [onerror]').length")
        b.close()
finally:
    for c in calls:
        c.terminate()
    proc.terminate()
print(json.dumps(out))
