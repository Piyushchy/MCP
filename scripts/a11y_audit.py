"""Accessibility audit of the admin page: axe-core (WCAG 2.1 A/AA), overflow at 360 and 1440 px, focus visibility.

Usage: python3 scripts/a11y_audit.py PY [AXE_JS]   (PY runs mcpgate; AXE_JS is an optional path to axe.min.js, MPL-2.0, not vendored)
Exits 1 if anything is found."""
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
PY = sys.argv[1]
AXE = Path(sys.argv[2]).read_text() if len(sys.argv) > 2 and sys.argv[2] else ""
PASS = "correct horse battery"
problems = []


def free():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(work, config):
    admin, pub = free(), free()
    (work / "mcpgate").mkdir(mode=0o700, parents=True)
    (work / "state" / "mcpgate").mkdir(parents=True, mode=0o700)
    cfg = work / "mcpgate" / "config.toml"
    cfg.write_text(config.format(admin=admin, pub=pub, repo=REPO, py=PY))
    cfg.chmod(0o600)
    env = {**os.environ, "MCPGATE_CONFIG": str(cfg), "XDG_STATE_HOME": str(work / "state"), "HOME": str(work)}
    env.pop("PYTHONPATH", None)
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
    return proc, admin, code


PAGES = [("overview", "ov"), ("backends", "bk"), ("secrets", "sec"), ("approvals", "ap"), ("remote", "rem"), ("tokens", "tok"), ("activity", "aud"), ("settings", "set")]


def visit(pg, route, key):
    pg.evaluate(f"location.hash = '#/{route}'")
    pg.locator(f"section[aria-labelledby={key}]").wait_for()
    pg.wait_for_timeout(300)


def check(page, label):
    unlabeled = page.evaluate("""() => [...document.querySelectorAll('input:not([type=hidden]),select,textarea')].filter(e => e.offsetParent !== null
        && !(e.labels && e.labels.length) && !e.getAttribute('aria-label') && !e.getAttribute('aria-labelledby')).map(e => e.name || e.id || e.type).slice(0, 5)""")
    if unlabeled:
        problems.append(f"{label}: form fields without a label: {unlabeled}")
    low = page.evaluate("""() => {
      const parse = (c) => { const m = c.match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1}; };
      const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
      const bgOf = (e) => { for (let n = e; n; n = n.parentElement) { const c = parse(getComputedStyle(n).backgroundColor); if (c && c.a > 0.99) return c; } return parse(getComputedStyle(document.body).backgroundColor) || {r: 255, g: 255, b: 255}; };
      const out = [];
      for (const e of document.querySelectorAll('body *')) {
        if (e.offsetParent === null || !e.textContent.trim() || ![...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue;
        const st = getComputedStyle(e); const fg = parse(st.color); if (!fg) continue;
        const L1 = lum(fg), L2 = lum(bgOf(e)); const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
        const big = parseFloat(st.fontSize) >= 24 || (parseFloat(st.fontSize) >= 18.66 && parseInt(st.fontWeight) >= 700);
        if (ratio < (big ? 3 : 4.5)) out.push(e.tagName.toLowerCase() + '.' + e.className + ' ' + ratio.toFixed(2));
      }
      return out.slice(0, 5); }""")
    if low:
        problems.append(f"{label}: low text contrast: {low}")
    res = []
    if AXE:
        page.add_script_tag(content=AXE)
        res = page.evaluate("""async () => { const r = await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21a','wcag21aa']}});
        return r.violations.map(v => ({id: v.id, n: v.nodes.length, help: v.help, sample: v.nodes[0].target.join(' '), why: (v.nodes[0].any[0]||v.nodes[0].all[0]||v.nodes[0].none[0]||{}).message})); }""")
    for v in res:
        problems.append(f"{label}: axe {v['id']} x{v['n']}: {v['help']} [{v['sample']}] {v['why']}")
    over = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    if over > 0:
        who = page.evaluate("""() => [...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > document.documentElement.clientWidth + 1 || e.scrollWidth > document.documentElement.clientWidth + 1)
            .slice(0, 4).map(e => e.tagName.toLowerCase() + '.' + e.className + '#' + e.id + ' w=' + e.scrollWidth + ' ' + (e.textContent || '').trim().slice(0, 30))""")
        problems.append(f"{label}: horizontal scroll of {over}px, wide elements: {who}")
    # keyboard: every interactive element must show a focus indicator when tabbed to
    bad = page.evaluate("""() => { const out = []; const els = [...document.querySelectorAll('a[href],button,input,select,textarea,summary,[tabindex]')]
        .filter(e => !e.disabled && e.offsetParent !== null && e.tabIndex >= 0);
        for (const e of els) { e.focus({focusVisible: true}); if (document.activeElement !== e) continue; const s = getComputedStyle(e);
          const ok = (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0) || s.boxShadow !== 'none';
          if (!ok) out.push(e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + ' ' + (e.textContent || e.getAttribute('aria-label') || '').trim().slice(0, 30)); }
        return out.slice(0, 5); }""")
    if bad:
        problems.append(f"{label}: no visible focus on {bad}")


with tempfile.TemporaryDirectory() as tmp, sync_playwright() as p:
    tmp = Path(tmp)
    browser = p.chromium.launch()
    base = '[server]\nadmin_port = {admin}\nport = {pub}\nwizard_done = true\n'
    demo = base + '[backends.demo]\ntransport = "stdio"\ncommand = "{py}"\nargs = ["{repo}/tests/fixtures/demo_server.py"]\nconfirm = ["create_*"]\n'
    for name, cfg in (("empty", base), ("demo", demo)):
        proc, admin, code = start(tmp / name, cfg)
        try:
            for scheme in ("light", "dark"):
                for w in (360, 1440):
                    label = f"{name}/{scheme}/{w}px"
                    ctx = browser.new_context(viewport={"width": w, "height": 900}, color_scheme=scheme, bypass_csp=True)
                    pg = ctx.new_page()
                    pg.goto(f"http://127.0.0.1:{admin}/")
                    if scheme == "light" and w == 360:
                        pg.get_by_label("Setup code").wait_for()
                        check(pg, label + "/setup")
                        pg.get_by_label("Setup code").fill(code)
                        pg.get_by_label("New passphrase (12+ characters)").fill(PASS)
                        pg.get_by_label("Repeat passphrase").fill(PASS)
                        pg.get_by_role("button", name="Create admin passphrase").click()
                    else:
                        pg.get_by_label("Passphrase").wait_for()
                        check(pg, label + "/signin")
                        pg.get_by_label("Passphrase").fill(PASS)
                        pg.get_by_role("button", name="Sign in").click()
                    pg.locator("nav[aria-label='Main menu']").wait_for()
                    for route, key in PAGES:
                        visit(pg, route, key)
                        if name == "demo" and route == "backends":
                            pg.locator("article.backend").first.wait_for()
                            pg.wait_for_timeout(1500)
                        if route == "remote":
                            pg.wait_for_timeout(500)
                        check(pg, f"{label}/{route}")
                    ctx.close()
        finally:
            proc.terminate()
    # the first-run guide, reopened from Settings, at both widths
    proc, admin, code = start(tmp / "wiz", base.replace("wizard_done = true\n", ""))
    try:
        for scheme in ("light", "dark"):
            for w in (360, 1440):
                ctx = browser.new_context(viewport={"width": w, "height": 900}, color_scheme=scheme, bypass_csp=True)
                pg = ctx.new_page()
                pg.goto(f"http://127.0.0.1:{admin}/")
                if scheme == "light" and w == 360:
                    pg.get_by_label("Setup code").fill(code)
                    pg.get_by_label("New passphrase (12+ characters)").fill(PASS)
                    pg.get_by_label("Repeat passphrase").fill(PASS)
                    pg.get_by_role("button", name="Create admin passphrase").click()
                else:
                    pg.get_by_label("Passphrase").fill(PASS)
                    pg.get_by_role("button", name="Sign in").click()
                pg.get_by_role("heading", name="Set up mcpgate").wait_for()
                pg.wait_for_timeout(500)
                check(pg, f"wizard/{scheme}/{w}px")
                ctx.close()
    finally:
        proc.terminate()
    # behaviour: unreachable service, expired session, keyboard-only sign-in
    proc, admin, code = start(tmp / "flow", base)
    try:
        ctx = browser.new_context(viewport={"width": 360, "height": 800})
        pg = ctx.new_page()
        pg.goto(f"http://127.0.0.1:{admin}/")
        pg.get_by_label("Setup code").fill(code)
        pg.get_by_label("New passphrase (12+ characters)").fill(PASS)
        pg.get_by_label("Repeat passphrase").fill(PASS)
        pg.get_by_role("button", name="Create admin passphrase").click()
        pg.locator("section[aria-labelledby=ov]").wait_for()
        if "Register a backend" not in pg.locator("section[aria-labelledby=ov]").inner_text():
            problems.append("the overview does not say what to do first")
        visit(pg, "backends", "bk")
        if "No backends yet. Add one" not in pg.locator("section[aria-labelledby=bk]").inner_text():
            problems.append("empty state does not say what to do next")
        pg.wait_for_timeout(1500)  # let the page finish drawing before the session is cut
        ctx.clear_cookies()  # the session ends while the page is open
        pg.get_by_role("button", name="Sign out").click()
        try:
            pg.locator("#f-passphrase").wait_for(timeout=5000)
        except Exception:
            problems.append("an expired session does not bring back the sign-in form")
        ctx.close()
        ctx = browser.new_context(viewport={"width": 360, "height": 800})
        pg = ctx.new_page()
        pg.route("**/api/session", lambda route: route.abort())
        pg.goto(f"http://127.0.0.1:{admin}/")
        try:
            pg.get_by_role("heading", name="Cannot reach mcpgate").wait_for(timeout=5000)
            pg.get_by_role("button", name="Try again").wait_for(timeout=1000)
        except Exception:
            problems.append("an unreachable service does not show the 'Cannot reach mcpgate' page")
        pg.unroute("**/api/session")
        pg.get_by_role("button", name="Try again").click()
        try:
            pg.locator("#f-passphrase").wait_for(timeout=5000)
        except Exception:
            problems.append("'Try again' does not recover once the service answers")
        pg.keyboard.press("Tab")  # keyboard only: the field, then Enter submits
        if pg.evaluate("document.activeElement && document.activeElement.id") != "f-passphrase":
            problems.append("the first Tab stop on the sign-in page is not the passphrase field")
        pg.keyboard.type(PASS)
        pg.keyboard.press("Enter")
        try:
            pg.locator("section[aria-labelledby=ov]").wait_for(timeout=5000)
        except Exception:
            problems.append("keyboard-only sign-in did not work")
        ctx.close()
    finally:
        proc.terminate()
    browser.close()

for line in problems:
    print("PROBLEM", line)
print(len(problems), "problems")
sys.exit(1 if problems else 0)
