"""XSS in a real browser. Needs Playwright with Chromium in some python3 on this machine; skipped otherwise."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent / "browser" / "xss_check.py"


def playwright_python():
    for name in ("python3", "python"):
        exe = shutil.which(name)
        if exe and subprocess.run([exe, "-c", "import playwright.sync_api"], capture_output=True).returncode == 0:
            return exe
    return None


@pytest.mark.skipif(playwright_python() is None, reason="Playwright is not installed here")
def test_hostile_values_from_backends_apps_and_logs_never_run_in_the_admin_page(tmp_path):
    r = subprocess.run([playwright_python(), str(SCRIPT), str(tmp_path), sys.executable], capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr[-2000:]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["pwned"] is None and out["dialogs"] == [] and out["page_errors"] == []
    assert out["injected_img"] == 0 and out["scripts"] == 1 and out["dom_img_with_src_x"] == 0
    for where, count in out["shown_in"].items():
        assert count >= 1, f"the payload should be visible as plain text in {where}"
