"""Accessibility and error-state checks in a real browser: contrast, labels, focus, phone-width overflow, expired
session, unreachable service, keyboard-only sign-in. Set MCPGATE_AXE to a path to axe.min.js to add axe-core too.
Needs Playwright with Chromium in some python3 on this machine; skipped otherwise."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "a11y_audit.py"


def playwright_python():
    for name in ("python3", "python"):
        exe = shutil.which(name)
        if exe and subprocess.run([exe, "-c", "import playwright.sync_api"], capture_output=True).returncode == 0:
            return exe
    return None


@pytest.mark.skipif(playwright_python() is None, reason="Playwright is not installed here")
def test_admin_page_is_accessible_and_recovers_from_errors():
    args = [playwright_python(), str(SCRIPT), sys.executable]
    if os.environ.get("MCPGATE_AXE"):
        args.append(os.environ["MCPGATE_AXE"])
    r = subprocess.run(args, capture_output=True, text=True, timeout=400)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
