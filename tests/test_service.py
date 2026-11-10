import subprocess
from pathlib import Path

import pytest

from mcpgate import service
from mcpgate.service import ServiceError, render_unit


class Fake:
    """Records systemctl/loginctl calls; behaves like a machine where systemd works."""

    def __init__(self, systemd=True, linger="no"):
        self.calls, self.systemd, self.linger = [], systemd, linger

    def __call__(self, cmd):
        self.calls.append(cmd)
        if cmd[0] == "systemctl" and not self.systemd:
            raise FileNotFoundError("systemctl")
        out = ""
        if cmd[:2] == ["loginctl", "show-user"]:
            out = self.linger + "\n"
        if cmd[:1] == ["loginctl"] and cmd[1] == "enable-linger":
            self.linger = "yes"
        if cmd[:3] == ["systemctl", "--user", "is-active"]:
            out = "active\n"
        return subprocess.CompletedProcess(cmd, 0, out, "")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    for k in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "MCPGATE_CONFIG"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


def test_unit_text_has_restart_and_nothing_secret():
    u = render_unit("/home/u/.local/bin/mcpgate", "/home/u/.local/bin:/usr/bin")
    assert 'ExecStart="/home/u/.local/bin/mcpgate" serve --service' in u and "Restart=always" in u and "RestartSec=3" in u
    assert "WantedBy=default.target" in u and "MCPGATE_CONFIG" not in u
    assert "0.0.0.0" not in u and "--host" not in u and "--http" not in u
    assert [line for line in u.splitlines() if line.startswith("Environment=")] == ['Environment="PATH=/home/u/.local/bin:/usr/bin"']


def test_unit_escapes_percent_quotes_and_rejects_line_breaks():
    u = render_unit('/home/we"ird/mcpgate', "/a%h:/b", "/c/100%/config.toml")
    assert 'ExecStart="/home/we\\"ird/mcpgate"' in u and 'PATH=/a%%h:/b' in u and "MCPGATE_CONFIG=/c/100%%/config.toml" in u
    for bad in ("/x\nExecStartPre=rm -rf /", "/x\rY"):
        with pytest.raises(ServiceError):
            render_unit("/x", bad)
        with pytest.raises(ServiceError):
            render_unit(bad, "/usr/bin")


def test_install_writes_the_unit_enables_restarts_and_turns_on_lingering(home):
    exe = home / "mcpgate"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    f = Fake()
    r = service.install(f, exe=str(exe), path_env="/usr/bin", config_file="")
    assert r["unit"] == str(home / ".config/systemd/user/mcpgate.service") and r["lingering"] is True and r["url"] == "http://127.0.0.1:8767"
    subs = [c[2:] if c[0] == "systemctl" else c for c in f.calls]
    assert ["daemon-reload"] in subs and ["enable", "mcpgate.service"] in subs and ["restart", "mcpgate.service"] in subs
    assert subs.index(["daemon-reload"]) < subs.index(["enable", "mcpgate.service"]) < subs.index(["restart", "mcpgate.service"])
    assert ["loginctl", "enable-linger", __import__("getpass").getuser()] in f.calls


def test_install_records_a_custom_config_and_leaves_no_temp_file(home):
    exe = home / "mcpgate"
    exe.write_text("x")
    service.install(Fake(), exe=str(exe), path_env="/usr/bin", config_file="/data/alt.toml")
    assert "MCPGATE_CONFIG=/data/alt.toml" in service.unit_path().read_text()
    assert [p.name for p in service.unit_dir().iterdir()] == ["mcpgate.service"]


def test_install_explains_when_there_is_no_systemd_or_no_command(home):
    with pytest.raises(ServiceError, match="systemd user services are not available"):
        service.install(Fake(systemd=False), exe="/x")
    with pytest.raises(ServiceError, match="cannot find the mcpgate command"):
        service.install(Fake(), exe=str(home / "missing"))
    with pytest.raises(ServiceError, match="cannot find the mcpgate command"):
        service.install(Fake(), exe="relative/mcpgate")


def test_a_failing_systemctl_step_is_reported_not_swallowed(home):
    exe = home / "mcpgate"
    exe.write_text("x")

    def runner(cmd):
        bad = cmd[:3] == ["systemctl", "--user", "enable"]
        return subprocess.CompletedProcess(cmd, 1 if bad else 0, "", "Failed to enable unit")
    with pytest.raises(ServiceError, match="enable"):
        service.install(runner, exe=str(exe), path_env="/usr/bin", config_file="")


def test_status_reports_state_and_survives_missing_systemd():
    s = service.status(Fake(linger="yes"))
    assert s["active"] == "active" and s["lingering"] is True and s["url"] == "http://127.0.0.1:8767" and s["unit_exists"] is False
    assert service.status(Fake(systemd=False))["active"] == "unknown"


def test_admin_url_follows_the_config_and_tolerates_a_broken_one(home):
    cfg = home / ".config" / "mcpgate"
    cfg.mkdir(parents=True)
    (cfg / "config.toml").write_text("[server]\nadmin_port = 9123\n")
    assert service.admin_url() == "http://127.0.0.1:9123"
    (cfg / "config.toml").write_text("[[[")
    assert service.admin_url() == "http://127.0.0.1:8767"


def test_uninstall_removes_the_unit_keeps_data_unless_purged(home):
    (home / ".config/systemd/user").mkdir(parents=True)
    service.unit_path().write_text("x")
    cfg, state = home / ".config/mcpgate", home / ".local/state/mcpgate"
    for d in (cfg, state):
        d.mkdir(parents=True)
        (d / "f").write_text("x")
    f = Fake()
    r = service.uninstall(f)
    assert not service.unit_path().exists() and cfg.exists() and state.exists() and set(r["kept"]) == {str(cfg), str(state)}
    assert ["systemctl", "--user", "disable", "--now", "mcpgate.service"] in f.calls
    r = service.uninstall(Fake(), purge=True)
    assert not cfg.exists() and not state.exists() and str(cfg) in r["removed"]


def test_purge_only_ever_touches_directories_named_mcpgate(home, monkeypatch):
    precious = home / "documents"
    precious.mkdir()
    (precious / "thesis.txt").write_text("x")
    monkeypatch.setenv("MCPGATE_CONFIG", str(precious / "config.toml"))        # a config kept in a shared folder
    monkeypatch.setenv("XDG_STATE_HOME", str(home / "state-root"))
    assert precious not in service.data_dirs()
    service.uninstall(Fake(), purge=True)
    assert (precious / "thesis.txt").exists()
