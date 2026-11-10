"""Run mcpgate as a systemd *user* service: starts at boot, restarts after a crash, survives closing SSH.

Only the admin UI (127.0.0.1) and, if you set up remote access, the loopback tunnel port are ever opened."""
from __future__ import annotations

import getpass
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import config as cfgmod
from . import oauth

UNIT = "mcpgate.service"


class ServiceError(Exception):
    pass


def run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def unit_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or "~/.config").expanduser() / "systemd" / "user"


def unit_path() -> Path:
    return unit_dir() / UNIT


def _quote(value: str) -> str:
    """One systemd Environment= or ExecStart word: quoted, with % and \\ and quotes escaped."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def executable() -> str:
    """Absolute path of the mcpgate command that is running now (what the unit starts)."""
    found = shutil.which("mcpgate")
    if found:
        return str(Path(found).absolute())
    return str(Path(sys.argv[0]).absolute())


def render_unit(exe: str, path_env: str, config_file: str = "") -> str:
    """The unit text. Environment is limited to PATH (so uvx, npx and friends are found) and the config location:
    no tokens, passphrases or other variables from the installing shell are copied into it."""
    if any(c in exe + path_env + config_file for c in "\r\n\x00"):
        raise ServiceError("paths may not contain line breaks")
    env = [f"Environment={_quote('PATH=' + path_env)}"]
    if config_file:
        env.append(f"Environment={_quote('MCPGATE_CONFIG=' + config_file)}")
    lines = [
        "[Unit]", "Description=mcpgate gateway and admin UI (admin UI on 127.0.0.1 only)",
        "After=network-online.target", "Wants=network-online.target", "",
        "[Service]", "Type=simple", f"ExecStart={_quote(exe)} serve --service", *env,
        "Restart=always", "RestartSec=3", "NoNewPrivileges=yes", "",
        "[Install]", "WantedBy=default.target", ""]
    return "\n".join(lines)


def _systemctl(runner, *args: str):
    return runner(["systemctl", "--user", *args])


def have_systemd_user(runner=run) -> bool:
    try:
        return _systemctl(runner, "show-environment").returncode == 0
    except FileNotFoundError:
        return False


def lingering(runner=run, user: str = "") -> bool:
    try:
        r = runner(["loginctl", "show-user", user or getpass.getuser(), "-p", "Linger", "--value"])
    except FileNotFoundError:
        return False
    return r.returncode == 0 and r.stdout.strip() == "yes"


def admin_url(config_file=None) -> str:
    """Where the admin page is. A missing or broken config must never stop an install or upgrade: use the default port."""
    try:
        path = Path(config_file) if config_file else cfgmod.config_path()
        s = cfgmod.load(path) if path.exists() else cfgmod.Settings()
    except Exception:  # noqa: BLE001
        s = cfgmod.Settings()
    return f"http://127.0.0.1:{s.server.admin_port}"


def install(runner=run, exe: str | None = None, path_env: str | None = None, config_file: str | None = None) -> dict:
    if not have_systemd_user(runner):
        raise ServiceError("systemd user services are not available here. Run `mcpgate serve --service` yourself, or from another service manager.")
    exe = exe or executable()
    if not os.path.isabs(exe) or not Path(exe).exists():
        raise ServiceError(f"cannot find the mcpgate command to run ({exe}). Install it with pipx or uv first.")
    cfg = config_file if config_file is not None else os.environ.get("MCPGATE_CONFIG", "")
    unit_dir().mkdir(parents=True, exist_ok=True)
    text = render_unit(exe, path_env if path_env is not None else os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), cfg)
    p = unit_path()
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, p)
    for args in (("daemon-reload",), ("enable", UNIT), ("restart", UNIT)):      # restart: a re-run upgrades the running copy
        r = _systemctl(runner, *args)
        if r.returncode != 0:
            raise ServiceError(f"systemctl {' '.join(args)} failed: {(r.stderr or r.stdout).strip()}")
    user = getpass.getuser()
    if not lingering(runner, user):
        runner(["loginctl", "enable-linger", user])
    return {"unit": str(p), "lingering": lingering(runner, user), "url": admin_url(cfg or None)}


def status(runner=run) -> dict:
    out = {"unit_exists": unit_path().exists(), "active": "unknown", "enabled": "unknown", "lingering": False, "url": admin_url()}
    if have_systemd_user(runner):
        out["active"] = _systemctl(runner, "is-active", UNIT).stdout.strip() or "inactive"
        out["enabled"] = _systemctl(runner, "is-enabled", UNIT).stdout.strip() or "disabled"
        out["lingering"] = lingering(runner)
    return out


def data_dirs() -> list[Path]:
    """Where mcpgate keeps its files. Only directories literally named 'mcpgate' are ever listed, so a
    mis-set variable can never make --purge delete something else."""
    dirs = [cfgmod.config_path().parent, oauth.default_state_path().parent]
    return [d for d in dict.fromkeys(dirs) if d.name == "mcpgate"]


def uninstall(runner=run, purge: bool = False) -> dict:
    removed = []
    if have_systemd_user(runner):
        for args in (("disable", "--now", UNIT),):
            _systemctl(runner, *args)
    p = unit_path()
    if p.exists():
        p.unlink()
        removed.append(str(p))
    if have_systemd_user(runner):
        _systemctl(runner, "daemon-reload")
        _systemctl(runner, "reset-failed", UNIT)
    if purge:
        for d in data_dirs():
            if d.exists():
                shutil.rmtree(d)
                removed.append(str(d))
    return {"removed": removed, "kept": [] if purge else [str(d) for d in data_dirs() if d.exists()]}
