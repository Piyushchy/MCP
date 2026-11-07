"""The `mcpgate` command."""
from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import shutil
import sys
from pathlib import Path

from . import __version__, custom
from . import config as cfgmod
from .audit import _SECRET_KEY
from .config import ENV_RE, Backend, ConfigError, Settings

STARTER = """\
# mcpgate config. Secrets do not go here: reference environment variables as ${NAME}.
#
# [gateway]
# cache_ttl = 60            # seconds a read-only result is reused (0 = off)
# max_result_chars = 20000  # longer text results are cut and can be paged
# audit_log = "~/.local/state/mcpgate/audit.jsonl"
#
# A local server started as a command:
# [backends.github]
# command = "npx"
# args = ["-y", "@modelcontextprotocol/server-github"]
# env = { GITHUB_PERSONAL_ACCESS_TOKEN = "${GITHUB_TOKEN}" }
# deny = ["delete_*"]          # hidden and uncallable
# confirm = ["create_*"]       # the model must get your OK first
#
# A remote server:
# [backends.docs]
# transport = "http"           # or "sse"
# url = "https://example.com/mcp"
# headers = { Authorization = "Bearer ${DOCS_TOKEN}" }
#
# Custom servers: drop a .py file into ~/.config/mcpgate/custom (see: mcpgate new NAME)
"""


def _settings(args, with_drop_ins: bool = True) -> Settings:
    s = cfgmod.load(args.config)
    return custom.with_custom(s) if with_drop_ins else s


def _kv(items: list[str], what: str) -> dict[str, str]:
    out = {}
    for item in items or []:
        key, eq, value = item.partition("=")
        if not eq or not key:
            raise ConfigError(f"{what} must look like NAME=VALUE, got {item!r}")
        if _SECRET_KEY.search(key) and not ENV_RE.search(value):
            raise ConfigError(
                f"{key} looks like a secret. Keep it out of the config file: set it in your environment "
                f"and pass {key}='${{{key}}}' (or another variable name) instead.")
        out[key] = value
    return out


# -- commands ---------------------------------------------------------------
def cmd_init(args) -> int:
    p = Path(args.config).expanduser() if args.config else cfgmod.config_path()
    if p.exists():
        print(f"{p} already exists.")
        return 0
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(STARTER)
    os.chmod(p, 0o600)
    print(f"Created {p}\nNext: mcpgate add NAME -- COMMAND ARGS...   (or edit the file)")
    return 0


def cmd_add(args) -> int:
    s = _settings(args, with_drop_ins=False)
    if args.name in s.backends:
        raise ConfigError(f"{args.name} already exists. Remove it first: mcpgate remove {args.name}")
    command = args.command
    b = Backend(name=args.name, description=args.description or "")
    if args.url:
        if command:
            raise ConfigError("give either --url or a command, not both")
        b.transport, b.url = ("sse" if args.sse else "http"), args.url
        b.headers = _kv(args.header, "--header")
    else:
        if not command:
            raise ConfigError("give a command after '--' (or use --url for a remote server)")
        b.command, b.args = command[0], command[1:]
        b.env = _kv(args.env, "--env")
    b.allow, b.deny, b.confirm = args.allow or ["*"], args.deny or [], args.confirm or []
    if args.timeout:
        b.timeout = args.timeout
    b.validate()
    s.backends[b.name] = b
    path = cfgmod.save(s, args.config)
    print(f"Added {b.name} to {path}. Check it with: mcpgate doctor")
    return 0


def cmd_remove(args) -> int:
    s = _settings(args, with_drop_ins=False)
    if args.name not in s.backends:
        raise ConfigError(f"no backend named {args.name!r} in the config file"
                          + (" (drop-in servers are removed by deleting their file)" if args.name in custom.discover(custom.folder(s)) else ""))
    del s.backends[args.name]
    cfgmod.save(s, args.config)
    print(f"Removed {args.name}.")
    return 0


def _toggle(args, enabled: bool) -> int:
    s = _settings(args, with_drop_ins=False)
    if args.name not in s.backends:
        raise ConfigError(f"no backend named {args.name!r} in the config file"
                          + (" (turn a drop-in server off by renaming its file to start with '_')" if args.name in custom.discover(custom.folder(s)) else ""))
    s.backends[args.name].enabled = enabled
    cfgmod.save(s, args.config)
    print(f"{'Enabled' if enabled else 'Disabled'} {args.name}.")
    return 0


def cmd_list(args) -> int:
    s = _settings(args)
    if not s.backends:
        print("No backends yet. Add one: mcpgate add NAME -- COMMAND ARGS...")
        return 0
    width = max(len(n) for n in s.backends)
    for name, b in sorted(s.backends.items()):
        where = b.url if b.transport != "stdio" else " ".join([b.command, *b.args])
        state = "on " if b.enabled else "off"
        extra = []
        if b.deny:
            extra.append(f"deny={len(b.deny)}")
        if b.confirm:
            extra.append(f"confirm={len(b.confirm)}")
        print(f"{name:<{width}}  {state}  {b.transport:<5}  {b.source:<6}  {where}" + (f"  [{' '.join(extra)}]" if extra else ""))
    return 0


def cmd_tools(args) -> int:
    from .hub import GatewayError, Hub
    from .trim import short

    async def run() -> int:
        hub = Hub(_settings(args))
        try:
            tools, errors = await hub.catalog(args.name)
        except GatewayError as e:
            print(e, file=sys.stderr)
            return 1
        finally:
            await hub.stop()
        for t in sorted(tools, key=lambda t: t.full):
            print(f"{t.full} — {short(t.description, 100)}")
        for n, m in errors.items():
            print(f"! {n}: {m}", file=sys.stderr)
        print(f"{len(tools)} tools", file=sys.stderr)
        return 1 if errors else 0

    return asyncio.run(run())


def cmd_new(args) -> int:
    s = _settings(args, with_drop_ins=False)
    try:
        p = custom.scaffold(s, args.name)
    except FileExistsError as e:
        raise ConfigError(f"{e} already exists") from None
    except ValueError as e:
        raise ConfigError(str(e)) from None
    print(f"Created {p}\nEdit it, then it appears as a backend automatically (check: mcpgate tools {custom.slug(args.name)})")
    return 0


def cmd_token(args) -> int:
    print(secrets.token_urlsafe(32))
    return 0


def _skill_text() -> str:
    from importlib import resources
    return resources.files("mcpgate").joinpath("data/skills/mcp-gateway/SKILL.md").read_text()


def cmd_skill(args) -> int:
    if args.action == "show":
        print(_skill_text(), end="")
        return 0
    base = Path(args.dir).expanduser() if args.dir else Path("~/.claude/skills").expanduser()
    target = base / "mcp-gateway" / "SKILL.md"
    if target.exists() and not args.force:
        raise ConfigError(f"{target} already exists (use --force to replace it)")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_skill_text())
    print(f"Installed {target}")
    return 0


def cmd_serve(args) -> int:
    from . import serve
    from .server import build
    s = _settings(args)
    kwargs = {}
    if args.http:
        token = os.environ.get(args.token_env) or None
        if not token and not serve.is_loopback(args.host):
            raise ConfigError(f"listening on {args.host} needs a token: set {args.token_env} (create one with: mcpgate token)")
        sec = serve.transport_security(args.allow_host or [])
        kwargs = {"host": args.host, "port": args.port, **({"transport_security": sec} if sec else {})}
    app, hub = build(s, **kwargs)
    if args.http:
        print(f"mcpgate listening on http://{args.host}:{args.port}/mcp"
              + (" (token required)" if token else " (no token, loopback only)"), file=sys.stderr)
        try:
            serve.run_http(app, hub, args.host, args.port, token)
        except ValueError as e:
            raise ConfigError(str(e)) from None
    else:
        serve.run_stdio(app, hub)
    return 0


def cmd_doctor(args) -> int:
    from .hub import Hub
    problems = 0

    def ok(msg): print(f"  ok    {msg}")
    def bad(msg):
        nonlocal problems
        problems += 1
        print(f"  FAIL  {msg}")

    path = Path(args.config).expanduser() if args.config else cfgmod.config_path()
    print(f"config: {path}" + ("" if path.exists() else " (not created yet, using defaults)"))
    s = _settings(args)  # a broken file raises ConfigError, reported by main()
    if path.exists() and (path.stat().st_mode & 0o077):
        bad(f"{path} is readable by other users; run: chmod 600 {path}")
    folder = custom.folder(s)
    drop_ins = [n for n, b in s.backends.items() if b.source == "custom"]
    print(f"custom folder: {folder} ({len(drop_ins)} server(s))")
    if not s.backends:
        print("  no backends yet")
        return 0

    for name, b in sorted(s.backends.items()):
        print(f"{name} ({b.transport}{', off' if not b.enabled else ''})")
        refs = set()
        for text in [b.command, b.url, *b.args, *b.env.values(), *b.headers.values(), b.cwd]:
            refs |= {m.group(1) for m in ENV_RE.finditer(text) if m.group(2) is None}
        for var in sorted(refs):
            (ok if os.environ.get(var) else bad)(f"environment variable {var} is {'set' if os.environ.get(var) else 'NOT set'}")
        if b.transport == "stdio" and "${" not in b.command:
            found = shutil.which(b.command) or (Path(b.command).is_file() and b.command)
            (ok if found else bad)(f"command {b.command!r} {'found' if found else 'not found on PATH'}")

    if not args.no_connect:
        async def probe():
            hub = Hub(s)
            try:
                for name, b in sorted(hub.backends.items()):
                    if not b.cfg.enabled:
                        continue
                    b.start_timeout = args.timeout
                    try:
                        tools = await b.tools()
                        vis = [t for t in tools if hub.policies[name].visible(t.name)]
                        ok(f"{name}: connected, {len(vis)} visible tool(s)" + (f" ({len(tools) - len(vis)} hidden by policy)" if len(vis) != len(tools) else ""))
                    except Exception as e:  # noqa: BLE001
                        bad(f"{name}: {e}")
            finally:
                await hub.stop()
        print("connecting...")
        asyncio.run(probe())
    print("all good" if not problems else f"{problems} problem(s)")
    return 1 if problems else 0


# -- wiring -------------------------------------------------------------------
def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcpgate", description="One MCP server that routes to many MCP servers.")
    p.add_argument("--version", action="version", version=f"mcpgate {__version__}")
    p.add_argument("--config", help="config file (default: $MCPGATE_CONFIG or ~/.config/mcpgate/config.toml)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the gateway (stdio by default)")
    s.add_argument("--http", action="store_true", help="listen over HTTP instead of stdio")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8766)
    s.add_argument("--token-env", default="MCPGATE_TOKEN", help="environment variable holding the bearer token")
    s.add_argument("--allow-host", action="append", help="extra Host header to accept (behind a tunnel)")
    s.set_defaults(fn=cmd_serve)

    sub.add_parser("init", help="create a starter config file").set_defaults(fn=cmd_init)

    a = sub.add_parser("add", help="add a backend: mcpgate add NAME -- COMMAND ARGS  |  mcpgate add NAME --url URL")
    a.add_argument("name")
    a.add_argument("--url", help="a remote MCP server (streamable HTTP, or SSE with --sse)")
    a.add_argument("--sse", action="store_true")
    a.add_argument("--env", action="append", metavar="NAME=${VAR}", help="environment for a command backend")
    a.add_argument("--header", action="append", metavar="NAME=VALUE", help="HTTP header for a remote backend")
    a.add_argument("--allow", action="append", metavar="GLOB", help="only these tools are visible (default: all)")
    a.add_argument("--deny", action="append", metavar="GLOB", help="hide and block these tools")
    a.add_argument("--confirm", action="append", metavar="GLOB", help="these tools need the user's approval")
    a.add_argument("--timeout", type=float, help="seconds to wait for a tool call (default 60)")
    a.add_argument("--description", help="one line shown in list_backends")
    a.set_defaults(fn=cmd_add)

    for name, fn, helptext in [("remove", cmd_remove, "remove a backend"),
                               ("enable", lambda x: _toggle(x, True), "turn a backend on"),
                               ("disable", lambda x: _toggle(x, False), "turn a backend off")]:
        c = sub.add_parser(name, help=helptext)
        c.add_argument("name")
        c.set_defaults(fn=fn)

    sub.add_parser("list", help="show configured backends").set_defaults(fn=cmd_list)
    t = sub.add_parser("tools", help="connect and list the tools a backend (or all) offers")
    t.add_argument("name", nargs="?")
    t.set_defaults(fn=cmd_tools)
    n = sub.add_parser("new", help="create a custom MCP server file from a template")
    n.add_argument("name")
    n.set_defaults(fn=cmd_new)
    sub.add_parser("token", help="print a new random bearer token").set_defaults(fn=cmd_token)
    k = sub.add_parser("skill", help="show or install the 'mcp-gateway' skill that teaches a model to use the gateway efficiently")
    k.add_argument("action", choices=["show", "install"])
    k.add_argument("--dir", help="skills folder to install into (default: ~/.claude/skills)")
    k.add_argument("--force", action="store_true")
    k.set_defaults(fn=cmd_skill)
    d = sub.add_parser("doctor", help="check the config, commands, secrets and connections")
    d.add_argument("--no-connect", action="store_true")
    d.add_argument("--timeout", type=float, default=20.0, help="seconds to wait for each backend to start")
    d.set_defaults(fn=cmd_doctor)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command: list[str] = []
    if "--" in argv:  # everything after '--' is the backend command, passed through untouched
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    args = parser().parse_args(argv)
    args.command = command
    if command and args.cmd != "add":
        print("error: '--' is only used with 'add'", file=sys.stderr)
        return 2
    try:
        return args.fn(args)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
