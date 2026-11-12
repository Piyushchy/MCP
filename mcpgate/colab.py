"""Support for the Google Colab backend: `mcpgate bridge colab`."""
from __future__ import annotations

import os
import shutil
from importlib import resources

SOURCE = "git+https://github.com/googlecolab/colab-mcp"     # set MCPGATE_COLAB_SOURCE to pin a version or use a local copy


def argv() -> list[str]:
    """The command that runs colab-mcp with the bridge. uvx keeps colab-mcp in its own cache, so there is no
    environment to create or clean up, nothing runs until the backend is first used, and it is shared and reused
    across restarts."""
    script = str(resources.files("mcpgate").joinpath("data/colab_bridge.py"))
    uvx = shutil.which("uvx")
    if not uvx:
        raise FileNotFoundError("uvx was not found. Install uv (https://docs.astral.sh/uv/) so mcpgate can run colab-mcp.")
    return [uvx, "--from", os.environ.get("MCPGATE_COLAB_SOURCE") or SOURCE, "python", script]


def run() -> int:
    cmd = argv()
    os.execv(cmd[0], cmd)        # replaces this process: no wrapper left running, stdio goes straight through
    return 0
