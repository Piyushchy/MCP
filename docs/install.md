# Install, upgrade and remove

## Install

On Ubuntu (or any Linux with systemd), as your normal user (not root):

```bash
git clone https://github.com/Piyushchy/MCP.git
cd MCP
./install.sh
```

The script:

1. installs the `mcpgate` command with **uv** (preferred) or **pipx**, using a Python 3.11 or newer
   (uv fetches one if needed; with pipx it uses what is installed and tells you if nothing is new enough);
2. installs and starts a **systemd user service** (`mcpgate.service`) that runs the gateway and the admin page;
3. turns on *lingering*, so the service keeps running after you log out and starts at boot;
4. prints the admin address, `http://127.0.0.1:8767`, and a one-time setup code.

Open the address in a browser on the same computer, enter the code, choose a passphrase. A guided setup then
walks you through adding your first backend. After that you never need the terminal.

What the installer does **not** do: it never asks for a password, token or key of yours (the only prompt you can
see is `sudo`, if pipx has to be installed from apt), it stores nothing secret, and it opens **no network port**.
The admin page listens on `127.0.0.1` only. The service's environment contains just `PATH` (so tools such as
`uvx` and `npx` are found) and, if you use one, the location of your config file.

The service restarts after a crash (`Restart=always`, 3 s delay) and after a reboot.

### Options (environment variables)

| Variable | Meaning |
|---|---|
| `MCPGATE_SKIP_APT=1` | never try to install system packages |
| `MCPGATE_NO_PULL=1` | do not run `git pull` before installing |
| `MCPGATE_NO_SERVICE=1` | install the command only; start the service later with `mcpgate service install` |
| `MCPGATE_WAIT=30` | seconds to wait for the admin page to come up |
| `MCPGATE_BIN_DIR` | where uv/pipx put the command (default `~/.local/bin`) |

## Upgrade

Run `./install.sh` again. It pulls the latest code (only if your clone has no local changes), reinstalls the
command, rewrites the unit, and restarts the service so the new version is running. Your config, secrets and
sign-ins are untouched.

## Day to day

```bash
mcpgate service status                 # running? starts at boot? keeps running after logout?
journalctl --user -u mcpgate -n 50     # recent log lines
mcpgate service install                # (re)install the service without touching the command
```

If you ever lose the admin passphrase: `mcpgate auth clear-admin`, then `mcpgate ui-code` for a new setup code.

## Reaching the admin page from another computer

The admin page is never exposed to the network, not even to your home network. To use it from your laptop while
mcpgate runs on a server, forward the port over SSH:

```bash
ssh -L 8767:127.0.0.1:8767 you@the-server
```

Keep that session open and browse to `http://127.0.0.1:8767` **on the laptop**. The page is served to your
laptop's own loopback through the encrypted SSH connection; nothing on the server listens on a public interface.
If 8767 is taken on the laptop, use another local port, for example `-L 9000:127.0.0.1:8767`, and open
`http://127.0.0.1:9000`. The admin page checks the `Host` header, so open it as `127.0.0.1` or `localhost`
with the port you forwarded, not through a reverse proxy.

## Uninstall

```bash
./install.sh uninstall            # stops and removes the service and the command; keeps your data
./install.sh uninstall --purge    # also deletes config, stored secrets and sign-ins (asks you to type DELETE)
```

Your data lives in `~/.config/mcpgate/` and `~/.local/state/mcpgate/`. Lingering is left on, because other user
services may rely on it; turn it off with `sudo loginctl disable-linger $USER` if you want.

## Testing the installer

Automated: `pytest tests/test_install_sh.py tests/test_service.py` runs the real script with stand-ins for
uv, pipx, systemctl, loginctl and sudo (install, upgrade, uninstall, purge, root refusal, no-systemd, no uv/pipx).

Manual, on a fresh Ubuntu machine (this is what the stand-ins cannot prove):

1. `./install.sh`. Expect the address, a setup code and "Ready". Open the address and finish the setup.
2. `systemctl --user status mcpgate` shows *active (running)*.
3. `ss -ltnp | grep -E '8766|8767'` shows only `127.0.0.1` addresses (never `0.0.0.0` or `*`).
4. Crash test: `kill -9 $(systemctl --user show -p MainPID --value mcpgate)`; within a few seconds the service is
   running again.
5. Log out of SSH completely, log in again: `mcpgate service status` still says running.
6. Reboot: the service is running again without you logging in (needs lingering: `loginctl show-user $USER -p Linger`).
7. `./install.sh` again: upgrade finishes, your data is intact, the page works.
8. `./install.sh uninstall`: the service and command are gone, `~/.config/mcpgate` is still there.
