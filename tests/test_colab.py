import os
from pathlib import Path

import pytest

from mcpgate import colab
from mcpgate.admin.addbackend import presets
from mcpgate.cli import ConfigError, main


def test_colab_preset_runs_the_built_in_bridge_not_a_hand_made_environment():
    b = presets()["colab"]["backend"]
    assert (b["command"], b["args"]) == ("mcpgate", ["bridge", "colab"])


def test_argv_runs_the_packaged_bridge_in_colab_mcps_own_cached_environment(tmp_path, monkeypatch):
    uvx = tmp_path / "uvx"
    uvx.write_text("#!/bin/sh\n")
    uvx.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("MCPGATE_COLAB_SOURCE", raising=False)
    cmd = colab.argv()
    assert cmd[:3] == [str(uvx), "--from", colab.SOURCE] and cmd[3] == "python"
    assert Path(cmd[4]).name == "colab_bridge.py" and Path(cmd[4]).is_file()
    monkeypatch.setenv("MCPGATE_COLAB_SOURCE", "git+https://example.invalid/colab-mcp@v1")
    assert colab.argv()[2] == "git+https://example.invalid/colab-mcp@v1"


def test_a_missing_uvx_gives_a_plain_message(monkeypatch, capsys):
    monkeypatch.setenv("PATH", "/nonexistent")
    assert main(["bridge", "colab"]) == 2
    assert "uvx was not found" in capsys.readouterr().err


def test_the_bridge_script_is_shipped_and_keeps_its_token_private():
    text = Path(colab.__file__).with_name("data").joinpath("colab_bridge.py").read_text()
    assert "0o600" in text and "webbrowser" in text and "PORT" in text
