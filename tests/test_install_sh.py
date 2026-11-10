"""install.sh end to end, with stand-ins for uv, pipx, systemctl, loginctl, sudo and id so it runs anywhere.
The mcpgate command itself, the unit file and the setup code are real."""
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SECRET = "super-secret-canary-4471"
PYTHON = sys.executable


def script(path: Path, body: str):
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


TOOL = r'''
# fake uv / pipx: "install" writes a wrapper that runs the real mcpgate from this repository
echo "$(basename "$0") $*" >> "$STATE/calls.log"
case "$*" in
  *"uninstall"*) rm -f "$HOME/.local/bin/mcpgate" ;;
  *"install"*)
    mkdir -p "$HOME/.local/bin"
    printf '#!/bin/sh\nPYTHONPATH="%s" exec "%s" -m mcpgate "$@"\n' "$REPO" "$PYTHON" > "$HOME/.local/bin/mcpgate"
    chmod +x "$HOME/.local/bin/mcpgate" ;;
  *"list"*) [ -x "$HOME/.local/bin/mcpgate" ] && echo "mcpgate v0.1.0" ;;
esac
exit 0
'''

SYSTEMCTL = r'''
echo "systemctl $*" >> "$STATE/calls.log"
shift   # --user
case "$1" in
  show-environment) exit 0 ;;
  enable) touch "$STATE/enabled" ;;
  restart) touch "$STATE/active" ;;
  disable) rm -f "$STATE/enabled" "$STATE/active" ;;
  is-active) [ -f "$STATE/active" ] && echo active || echo inactive ;;
  is-enabled) [ -f "$STATE/enabled" ] && echo enabled || echo disabled ;;
esac
exit 0
'''

LOGINCTL = r'''
echo "loginctl $*" >> "$STATE/calls.log"
case "$1" in
  show-user) [ -f "$STATE/linger" ] && echo yes || echo no ;;
  enable-linger) [ "${LINGER_ALLOWED:-1}" = 1 ] && touch "$STATE/linger" ;;
esac
exit 0
'''


@pytest.fixture
def box(tmp_path):
    stubs, state, home = tmp_path / "stubs", tmp_path / "state", tmp_path / "home"
    for d in (stubs, state, home):
        d.mkdir()
    # only these real tools are visible to the script: no real uv, pipx, apt-get or sudo can leak in
    for tool in ("bash", "sh", "env", "uname", "grep", "sed", "dirname", "basename", "seq", "sleep", "rm", "mkdir", "cat", "touch", "chmod", "git", "python3",
                 "python3.11", "python3.12", "python3.13", "printf", "tee", "tr", "id_real"):
        found = shutil.which(tool, path="/usr/bin:/bin:/usr/local/bin")
        if found:
            (stubs / tool).symlink_to(found)
    script(stubs / "uv", TOOL)
    script(stubs / "systemctl", SYSTEMCTL)
    script(stubs / "loginctl", LOGINCTL)
    script(stubs / "sudo", 'echo "sudo $*" >> "$STATE/calls.log"; exit 1\n')           # must never be needed
    script(stubs / "id", 'if [ "$1" = "-u" ]; then echo "${FAKE_UID:-1000}"; else /usr/bin/id "$@"; fi\n')

    class Box:
        pass
    b = Box()
    b.stubs, b.state, b.home, b.tmp = stubs, state, home, tmp_path
    b.env = {"HOME": str(home), "USER": "tester", "STATE": str(state), "REPO": str(REPO), "PYTHON": PYTHON, "MCPGATE_NO_PULL": "1",
             "MCPGATE_WAIT": "1", "PATH": str(stubs), "SECRET_CANARY": SECRET, "LANG": "C"}
    b.run = lambda *args, **env: subprocess.run(["bash", str(REPO / "install.sh"), *args], env={**b.env, **env}, capture_output=True, text=True, timeout=120, input="")
    b.calls = lambda: (state / "calls.log").read_text() if (state / "calls.log").exists() else ""
    b.unit = home / ".config" / "systemd" / "user" / "mcpgate.service"
    return b


def test_fresh_install(box):
    r = box.run()
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "Admin page (this computer only):  http://127.0.0.1:8767" in out
    assert re.search(r"[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}", out), "the one-time setup code is printed"
    assert "ssh -L 8767:127.0.0.1:8767" in out
    unit = box.unit.read_text()
    assert f'ExecStart="{box.home}/.local/bin/mcpgate" serve --service' in unit
    assert "Restart=always" in unit and "WantedBy=default.target" in unit
    assert SECRET not in unit and "0.0.0.0" not in unit and f"PATH={box.home}/.local/bin" in unit
    c = box.calls()
    assert "uv tool install --force --python >=3.11" in c and "systemctl --user enable mcpgate.service" in c and "systemctl --user restart mcpgate.service" in c
    assert "loginctl enable-linger tester" in c and "sudo" not in c
    assert (box.state / "linger").exists() and (box.state / "enabled").exists()


def test_rerun_upgrades_in_place(box):
    assert box.run().returncode == 0
    r = box.run()
    assert r.returncode == 0, r.stdout + r.stderr
    c = box.calls()
    assert c.count("uv tool install") == 2 and c.count("systemctl --user restart mcpgate.service") == 2      # new code is running afterwards
    assert box.unit.exists()


def test_already_configured_admin_is_not_asked_for_a_code_again(box):
    assert box.run().returncode == 0
    code = f'''
import sys
sys.path.insert(0, {str(REPO)!r})
from mcpgate.admin.session import AdminAuth
from mcpgate.authstore import AuthStore
a = AdminAuth(AuthStore())
a.setup(a.issue_setup_code(), "an admin passphrase that is long")
'''
    env = {**box.env, "XDG_CONFIG_HOME": "", "XDG_STATE_HOME": ""}
    assert subprocess.run([PYTHON, "-c", code], env=env, capture_output=True, text=True).returncode == 0
    r = box.run()
    assert r.returncode == 0 and "already set" in r.stdout and not re.search(r"[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}", r.stdout)


def test_without_permission_to_linger_it_says_what_to_run_and_never_uses_sudo_password(box):
    r = box.run(LINGER_ALLOWED="0")
    assert r.returncode == 0 and "sudo loginctl enable-linger" in r.stdout
    assert not any(line.startswith("sudo ") and "-n" not in line for line in box.calls().splitlines())


def test_uninstall_keeps_data_and_purge_deletes_it(box):
    assert box.run().returncode == 0
    cfg = box.home / ".config" / "mcpgate"
    state = box.home / ".local" / "state" / "mcpgate"
    cfg.mkdir(parents=True, exist_ok=True)
    state.mkdir(parents=True, exist_ok=True)
    (cfg / "config.toml").write_text("[server]\nadmin_port = 8767\n")
    (state / "oauth.json").write_text("{}")
    r = box.run("uninstall")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not box.unit.exists() and not (box.home / ".local/bin/mcpgate").exists()
    assert (cfg / "config.toml").exists() and "kept" in r.stdout.lower()
    assert "systemctl --user disable --now mcpgate.service" in box.calls()
    # a second round: reinstall, then purge
    assert box.run().returncode == 0
    r = box.run("uninstall", "--purge", "--yes")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not cfg.exists() and not state.exists() and not box.unit.exists()


def test_a_broken_config_does_not_stop_an_upgrade(box):
    cfg = box.home / ".config" / "mcpgate"
    cfg.mkdir(parents=True)
    (cfg / "config.toml").write_text("this is [not valid")
    r = box.run()
    assert r.returncode == 0 and "http://127.0.0.1:8767" in r.stdout


def test_purge_without_yes_asks_and_cancels_on_anything_but_delete(box):
    assert box.run().returncode == 0
    cfg = box.home / ".config" / "mcpgate"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "config.toml").write_text("x")
    r = box.run("uninstall", "--purge")          # stdin is empty: the question gets no answer
    assert (cfg / "config.toml").exists() and r.returncode != 0


def test_uninstall_when_the_command_is_already_gone_still_removes_the_service(box):
    assert box.run().returncode == 0
    (box.home / ".local/bin/mcpgate").unlink()
    r = box.run("uninstall")
    assert r.returncode == 0 and not box.unit.exists()


def test_pipx_is_used_when_there_is_no_uv(box):
    (box.stubs / "uv").rename(box.stubs / "pipx")
    r = box.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert "pipx install --force --python" in box.calls() and "uv " not in box.calls()


def test_without_uv_or_pipx_it_explains_and_stops(box):
    (box.stubs / "uv").unlink()
    r = box.run(MCPGATE_SKIP_APT="1")
    assert r.returncode == 1 and "neither uv nor pipx" in r.stderr and not box.unit.exists()


def test_refuses_to_run_as_root(box):
    r = box.run(FAKE_UID="0")
    assert r.returncode == 1 and "not root" in r.stderr and not box.unit.exists()


def test_must_be_run_from_the_repository(box, tmp_path):
    lone = tmp_path / "elsewhere"
    lone.mkdir()
    shutil.copy(REPO / "install.sh", lone / "install.sh")
    r = subprocess.run(["bash", str(lone / "install.sh")], env=box.env, capture_output=True, text=True)
    assert r.returncode == 1 and "root of the mcpgate repository" in r.stderr


def test_unknown_action_and_help(box):
    assert box.run("frobnicate").returncode == 1
    h = box.run("--help")
    assert h.returncode == 0 and "./install.sh uninstall" in h.stdout


def test_command_only_mode_installs_no_service(box):
    r = box.run(MCPGATE_NO_SERVICE="1")
    assert r.returncode == 0 and not box.unit.exists() and "systemctl" not in box.calls()


def test_the_script_never_prompts_for_or_handles_secrets_and_opens_no_network_port():
    text = (REPO / "install.sh").read_text()
    assert not re.search(r"^\s*read\b|\bread -", text, re.M)
    assert "0.0.0.0" not in text and "--host" not in text and "nc -l" not in text
    for line in text.splitlines():
        code = re.sub(r'"[^"]*"', "", line.strip())      # words inside messages do not count
        if "sudo" in code and not code.startswith("#"):
            assert "sudo -n loginctl enable-linger" in code or "sudo apt-get" in code or "sudo env DEBIAN_FRONTEND" in code, code
