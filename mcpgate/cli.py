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


def _secrets():
    from .secretstore import SecretStore
    return SecretStore()


def _reloader(hub, args):
    from .reload import Reloader
    return Reloader(hub, args.config)


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
        b.transport, b.url = ("sse" if args.sse else "http"), cfgmod.check_backend_url(args.url)
        b.headers = _kv(args.header, "--header")
    else:
        if not command:
            raise ConfigError("give a command after '--' (or use --url for a remote server)")
        b.command, b.args = command[0], command[1:]
        b.env = _kv(args.env, "--env")
    b.allow, b.deny, b.confirm = args.allow or ["*"], args.deny or [], args.confirm or []
    if args.timeout:
        b.timeout = args.timeout
    if args.start_timeout:
        b.start_timeout = args.start_timeout
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
        hub = Hub(_settings(args), secrets=_secrets())
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


def _auth_store():
    from .authstore import AuthStore
    return AuthStore()


def _admin(srv, hub, reloader, args):
    from .admin.app import AdminError, AdminServer
    from .admin.context import AdminContext
    from .admin.session import AdminAuth
    auth = AdminAuth(_auth_store(), audit=lambda **f: hub.audit.log(**f))
    ctx = AdminContext(hub, args.config, reloader, hub.secrets, auth)
    try:
        server = AdminServer(srv.admin_port, auth=auth, ctx=ctx)
    except AdminError as e:
        raise ConfigError(str(e)) from None
    if auth.state() == "setup":
        print(f"First run: open http://127.0.0.1:{srv.admin_port} and enter this setup code (works once, 30 minutes):\n"
              f"    {auth.issue_setup_code()}\nLost it? Run: mcpgate ui-code", file=sys.stderr)
    else:
        print(f"Admin UI: http://127.0.0.1:{srv.admin_port}", file=sys.stderr)
    return server


def cmd_ui_code(args) -> int:
    from .admin.session import AdminAuth
    auth = AdminAuth(_auth_store())
    if auth.state() != "setup":
        raise ConfigError("the admin passphrase is already set. To reset it, run: mcpgate auth clear-admin")
    print(f"Setup code (works once, for 30 minutes; replaces any earlier code):\n    {auth.issue_setup_code()}")
    return 0


def cmd_serve(args) -> int:
    from . import oauth as oauthmod
    from . import serve
    from .config import check_public_url
    from .server import build
    s = _settings(args)
    srv = s.server
    kwargs: dict = {}
    oauth = None
    token = None
    verify = None
    if args.service:
        # the service always runs the admin UI; the public listener only exists when remote access is configured
        auth0 = _auth_store()
        remote = bool(args.public_url or (srv.oauth_enabled and srv.public_url) or os.environ.get(args.token_env)
                      or (srv.static_token_enabled and auth0.has("static_token")))
        args.http = remote
    if args.public_url and not args.http:
        raise ConfigError("--public-url only makes sense with --http")
    if args.http:
        host = args.host
        port = args.port if args.port is not None else srv.port
        auth = _auth_store()
        token = os.environ.get(args.token_env) or None
        static_hashed = srv.static_token_enabled and auth.has("static_token")
        if not token and static_hashed:
            verify = lambda given: auth.verify("static_token", given)  # noqa: E731
        # OAuth turns on with --public-url, or with [server] oauth_enabled and a public_url
        public_url = args.public_url or (srv.public_url if srv.oauth_enabled else "")
        if public_url:
            url = check_public_url(public_url)
            env_pass = os.environ.get(args.passphrase_env) or None
            if env_pass is None and not auth.has("oauth_passphrase"):
                raise ConfigError(f"no approval passphrase is set: run 'mcpgate auth passphrase' "
                                  f"(or set {args.passphrase_env} to one of at least {oauthmod.MIN_PASSPHRASE} characters)")
            hosts = list(oauthmod.DEFAULT_REDIRECT_HOSTS) + list(srv.oauth_redirect_hosts) + list(args.oauth_redirect_host or [])
            state = Path(args.state_file).expanduser() if args.state_file else None
            try:
                oauth = oauthmod.GatewayOAuth(url, env_pass, state, hosts, static_token=token, auth=auth,
                                              static_from_auth=static_hashed and not token)
            except ValueError as e:
                raise ConfigError(str(e)) from None
        elif not token and not verify and not serve.is_loopback(host):
            raise ConfigError(f"listening on {host} needs a token or OAuth: run 'mcpgate auth token' "
                              f"(or set {args.token_env}), or set a public address for OAuth")
        sec = serve.transport_security(list(args.allow_host or []) + list(srv.allow_hosts))
        kwargs = {"host": host, "port": port, **({"transport_security": sec} if sec else {})}
    from .hub import Hub
    app, hub = build(s, hub=Hub(s, secrets=_secrets()), oauth=oauth, **kwargs)
    if args.http:
        how = ("OAuth (passphrase approval)" + (" and static token" if (token or verify) else "")) if oauth else (
            "token required" if (token or verify) else "no token, loopback only")
        print(f"mcpgate listening on http://{host}:{port}/mcp ({how})", file=sys.stderr)
        if oauth:
            print(f"Add this URL in claude.ai (Customize > Connectors > Add custom connector): {oauth.public_url}/mcp", file=sys.stderr)
        try:
            if args.service:
                public = serve.make_http_server(app, host, port, token, oauth is not None, verify)
                rl = _reloader(hub, args)
                serve.run_service(hub, public, _admin(srv, hub, rl, args), reloader=rl)
            else:
                serve.run_http(app, hub, host, port, token, oauth=oauth is not None, reloader=_reloader(hub, args), verify=verify)
        except ValueError as e:
            raise ConfigError(str(e)) from None
    elif args.service:
        print(f"mcpgate service: admin UI on http://127.0.0.1:{srv.admin_port} (no remote access configured yet)", file=sys.stderr)
        rl = _reloader(hub, args)
        serve.run_service(hub, None, _admin(srv, hub, rl, args), reloader=rl)
    else:
        serve.run_stdio(app, hub, reloader=_reloader(hub, args))
    return 0


def cmd_secret(args) -> int:
    """Store a value a backend needs. The value is typed hidden and can never be shown again."""
    import getpass
    store = _secrets()
    if args.action == "list":
        rows = store.names()
        for r in rows:
            print(f"{r['name']:<32} set")
        if not rows:
            print("no secrets stored")
        return 0
    if not args.name:
        raise ConfigError(f"usage: mcpgate secret {args.action} NAME")
    if args.action == "set":
        value = getpass.getpass(f"Value for {args.name} (hidden): ")
        store.set(args.name, value)
        print(f"Saved {args.name}. It cannot be shown again, only replaced or removed.")
        return 0
    print("Removed." if store.delete(args.name) else "It was not set.")
    return 0


def cmd_auth(args) -> int:
    """Set the credentials the gateway checks. Only hashes are stored; nothing is printed back except a new token, once."""
    import getpass

    from .authstore import MIN_PASSPHRASE, AuthStore, new_token
    store = AuthStore()
    if args.action == "status":
        for name, label in [("oauth_passphrase", "approval passphrase (claude.ai)"), ("static_token", "static bearer token"),
                            ("admin_passphrase", "admin UI passphrase")]:
            print(f"{label:<34} {'set' if store.has(name) else 'not set'}")
        return 0
    if args.action == "passphrase":
        first = getpass.getpass(f"New approval passphrase (min {MIN_PASSPHRASE} characters): ")
        if first != getpass.getpass("Repeat it: "):
            raise ConfigError("the two entries do not match")
        try:
            store.set_passphrase("oauth_passphrase", first)
        except ConfigError:
            raise
        print("Saved. Only a salted hash is stored.")
        return 0
    if args.action == "token":
        t = new_token()
        store.set_token("static_token", t)
        s = cfgmod.load(args.config)
        s.server.static_token_enabled = True
        cfgmod.save(s, args.config)
        print(f"New token (shown once, save it now):\n{t}")
        return 0
    name = {"clear-passphrase": "oauth_passphrase", "clear-token": "static_token", "clear-admin": "admin_passphrase"}[args.action]
    print("Removed." if store.clear(name) else "It was not set.")
    return 0


def cmd_oauth(args) -> int:
    from . import oauth as oauthmod
    path = Path(args.state_file).expanduser() if args.state_file else oauthmod.default_state_path()
    if not path.exists():
        print(f"No OAuth state yet ({path}).")
        return 0
    store = oauthmod.Store(path)
    if args.action == "status":
        now = __import__("time").time()
        live = sum(1 for v in store.data["refresh"].values() if v["exp"] > now)
        print(f"{path}\n{len(store.data['clients'])} registered app(s), {live} signed-in session(s)")
        return 0
    store.clear()  # a running gateway notices the change and refuses every old token
    print("Signed out everywhere: all registered apps and tokens were removed.")
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
    store = _secrets()
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
            where = "environment" if os.environ.get(var) else "secrets store" if store.has(var) else ""
            (ok if where else bad)(f"{var} is {'set (' + where + ')' if where else 'NOT set (mcpgate secret set ' + var + ')'}")
        if b.transport == "stdio" and "${" not in b.command:
            found = shutil.which(b.command) or (Path(b.command).is_file() and b.command)
            (ok if found else bad)(f"command {b.command!r} {'found' if found else 'not found on PATH'}")

    if not args.no_connect:
        async def probe():
            hub = Hub(s, secrets=store)
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
    s.add_argument("--service", action="store_true", help="run as the long-lived service: local admin UI always, public listener only if remote access is set up")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=None, help="listen port (default: [server] port, 8766)")
    s.add_argument("--token-env", default="MCPGATE_TOKEN", help="environment variable holding the bearer token")
    s.add_argument("--allow-host", action="append", help="extra Host header to accept (behind a tunnel)")
    s.add_argument("--public-url", help="the public https address (your Funnel URL) to turn on OAuth for claude.ai")
    s.add_argument("--passphrase-env", default="MCPGATE_PASSPHRASE", help="environment variable with the approval passphrase")
    s.add_argument("--state-file", help="where OAuth clients and token hashes are kept (default: ~/.local/state/mcpgate/oauth.json)")
    s.add_argument("--oauth-redirect-host", action="append", help="allow another app's redirect host (default: claude.ai and localhost)")
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
    a.add_argument("--start-timeout", type=float, help="seconds to wait for the server to start (default 30; raise it for a first npx/uvx download)")
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
    o = sub.add_parser("oauth", help="see or reset the apps signed in through OAuth")
    o.add_argument("action", choices=["status", "revoke-all"])
    o.add_argument("--state-file")
    o.set_defaults(fn=cmd_oauth)
    sc = sub.add_parser("secret", help="store tokens and API keys that backends reference as ${NAME} (write-only)")
    sc.add_argument("action", choices=["set", "list", "remove"])
    sc.add_argument("name", nargs="?")
    sc.set_defaults(fn=cmd_secret)
    au = sub.add_parser("auth", help="set the approval passphrase / static token (stored only as hashes)")
    au.add_argument("action", choices=["status", "passphrase", "token", "clear-passphrase", "clear-token", "clear-admin"])
    au.set_defaults(fn=cmd_auth)
    sub.add_parser("ui-code", help="print a one-time code to set the admin UI passphrase on first run").set_defaults(fn=cmd_ui_code)
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
