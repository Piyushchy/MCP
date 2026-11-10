#!/usr/bin/env bash
# mcpgate installer. Run it from a clone of the repository, as your normal user (not root):
#
#     git clone https://github.com/Piyushchy/MCP.git
#     cd MCP
#     ./install.sh              # install, or upgrade if already installed
#     ./install.sh uninstall    # remove the service and the command, keep your data
#     ./install.sh uninstall --purge   # ... and delete config, secrets and sign-ins (asks first)
#
# It installs the `mcpgate` command with uv or pipx, installs and starts a systemd *user* service that runs the
# gateway with the admin page, turns on lingering so it keeps running after you log out, and prints the admin
# address and a one-time setup code. After that, everything is done in the browser.
#
# It never asks for or stores a secret and opens no port other than the loopback ones (127.0.0.1).
# The admin page is reachable only from this computer. From another computer use an SSH tunnel:
#     ssh -L 8767:127.0.0.1:8767 you@this-computer      then open http://127.0.0.1:8767
#
# Optional environment variables (mostly for testing):
#   MCPGATE_BIN_DIR      where the command is installed by uv/pipx   (default ~/.local/bin)
#   MCPGATE_SKIP_APT=1   never try to install system packages
#   MCPGATE_NO_PULL=1    do not run `git pull` before installing
#   MCPGATE_NO_SERVICE=1 install the command only, no background service
#   MCPGATE_WAIT=30      seconds to wait for the admin page to come up
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${MCPGATE_BIN_DIR:-$HOME/.local/bin}"
WAIT="${MCPGATE_WAIT:-30}"

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

ACTION="${1:-install}"
[ $# -gt 0 ] && shift
case "$ACTION" in
  install|uninstall) ;;
  -h|--help|help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) die "unknown action '$ACTION' (use: install, uninstall)" ;;
esac

[ "$(uname -s)" = "Linux" ] || die "this installer is for Linux (Ubuntu)"
[ "$(id -u)" -ne 0 ] || die "run this as your normal user, not root: the service belongs to your account"
ORIG_PATH="$PATH"
export PATH="$BIN_DIR:$PATH"

# ------------------------------------------------------------------------------------------------ uninstall
if [ "$ACTION" = "uninstall" ]; then
  say "Removing the mcpgate service"
  if have mcpgate; then
    mcpgate service uninstall "$@"
  else
    echo "the mcpgate command is not installed; removing the service files directly"
    have systemctl && systemctl --user disable --now mcpgate.service >/dev/null 2>&1 || true
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/mcpgate.service"
    have systemctl && systemctl --user daemon-reload >/dev/null 2>&1 || true
  fi
  say "Removing the mcpgate command"
  if have uv && uv tool list 2>/dev/null | grep -q '^mcpgate '; then uv tool uninstall mcpgate
  elif have pipx && pipx list --short 2>/dev/null | grep -q '^mcpgate '; then pipx uninstall mcpgate
  else echo "nothing to remove"; fi
  echo
  echo "Done. Lingering (keeps your user services running after logout) was left on because other services may use it."
  echo "Turn it off with: sudo loginctl disable-linger \$USER"
  exit 0
fi

# -------------------------------------------------------------------------------------------------- install
[ -f "$SRC/pyproject.toml" ] && grep -q '^name = "mcpgate"' "$SRC/pyproject.toml" || die "run this from the root of the mcpgate repository"

if [ "${MCPGATE_NO_PULL:-0}" != "1" ] && [ -d "$SRC/.git" ] && have git; then
  if [ -z "$(git -C "$SRC" status --porcelain 2>/dev/null)" ]; then
    say "Checking for updates"
    git -C "$SRC" pull --ff-only --quiet 2>/dev/null && echo "up to date" || echo "could not update; installing the files that are here"
  else
    echo "local changes found in $SRC; not updating it, installing the files that are here"
  fi
fi

find_python() {   # a python of version 3.11 or newer, for pipx
  local c
  for c in python3.13 python3.12 python3.11 python3; do
    if have "$c" && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then command -v "$c"; return 0; fi
  done
  return 1
}

if have uv; then
  say "Installing mcpgate with uv"
  uv tool install --force --python '>=3.11' "$SRC"
else
  if ! have pipx && [ "${MCPGATE_SKIP_APT:-0}" != "1" ] && have apt-get; then
    say "Installing pipx (this asks for your sudo password; mcpgate itself never does)"
    sudo apt-get update -y -qq && sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq pipx || true
  fi
  have pipx || die "neither uv nor pipx is installed. Install uv (https://docs.astral.sh/uv/) or run: sudo apt install pipx   then run ./install.sh again"
  PY="$(find_python)" || die "mcpgate needs Python 3.11 or newer. Install it (sudo apt install python3.12) or install uv, which fetches one for you, then run ./install.sh again"
  say "Installing mcpgate with pipx ($PY)"
  pipx install --force --python "$PY" "$SRC"
fi

[ -x "$BIN_DIR/mcpgate" ] || die "the mcpgate command was not found in $BIN_DIR after installing (set MCPGATE_BIN_DIR if your tool puts it elsewhere)"
case ":$ORIG_PATH:" in *":$BIN_DIR:"*) ;; *) echo "note: add $BIN_DIR to your PATH:  export PATH=\"$BIN_DIR:\$PATH\"  (pipx ensurepath does this)";; esac

if [ "${MCPGATE_NO_SERVICE:-0}" = "1" ]; then
  say "Installed the command. Start the service later with: mcpgate service install"
  exit 0
fi

say "Installing and starting the background service"
mcpgate service install

if ! loginctl show-user "$USER" -p Linger --value 2>/dev/null | grep -qx yes; then
  sudo -n loginctl enable-linger "$USER" 2>/dev/null || true
  loginctl show-user "$USER" -p Linger --value 2>/dev/null | grep -qx yes \
    || echo "note: to keep it running after you log out, run once:  sudo loginctl enable-linger \$USER"
fi

URL="$(mcpgate service status | sed -n 's/^admin page: //p')"
PORT="${URL##*:}"
say "Waiting for the admin page"
up=0
for _ in $(seq 1 "$WAIT"); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then up=1; break; fi
  sleep 1
done
[ "$up" = 1 ] || echo "it is not answering yet. Check:  mcpgate service status   and   journalctl --user -u mcpgate -n 30"

say "Ready"
echo "Admin page (this computer only):  $URL"
if code_out="$(mcpgate ui-code 2>/dev/null)"; then
  echo
  echo "$code_out"
  echo "Open the page, enter this code and choose your admin passphrase."
else
  echo "The admin passphrase is already set. Open the page and sign in."
fi
echo
echo "From another computer, use an SSH tunnel (nothing listens on the network):"
echo "    ssh -L $PORT:127.0.0.1:$PORT you@this-computer      then open $URL"
echo "To remove it:  ./install.sh uninstall"
