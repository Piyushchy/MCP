# mcpgate

One MCP server that routes to many MCP servers.

You connect your AI client to `mcpgate` once. Behind it sit any number of other MCP servers (GitHub,
files, mail, remote servers, or ones you write yourself). Instead of loading hundreds of tool
definitions into the model's context, the gateway exposes five small tools and lets the model **search
for the tool it needs**, then call it.

```
 AI client ──MCP──►  mcpgate  ──┬─ stdio  ► npx @modelcontextprotocol/server-github
 (Claude, etc.)    5 meta-tools ├─ http   ► https://example.com/mcp
                    policy,     ├─ sse    ► https://legacy.example/sse
                    cache,      └─ custom ► ~/.config/mcpgate/custom/notes.py
                    audit log
```

## Why

- **Smaller context.** Ten servers can mean 200+ tool schemas in every request. Here the client sees five tools.
- **One place for control.** Allow/deny lists, approval for risky tools, secrets kept in one place, one audit log.
- **Your own servers are easy.** Drop a `.py` file in a folder; it becomes a backend.

## Install

Needs Python 3.11+.

```bash
pipx install git+https://github.com/Piyushchy/MCP     # or: pip install git+https://github.com/Piyushchy/MCP
mcpgate init                                          # creates ~/.config/mcpgate/config.toml (mode 600)
```

## Quick start

```bash
# a local server started as a command (everything after -- is the command)
mcpgate add github --env GITHUB_PERSONAL_ACCESS_TOKEN='${GITHUB_TOKEN}' \
    --deny 'delete_*' --confirm 'create_*' -- npx -y @modelcontextprotocol/server-github

# a remote server
mcpgate add docs --url https://example.com/mcp --header 'Authorization=Bearer ${DOCS_TOKEN}'

mcpgate doctor          # checks the config, commands, environment variables and live connections
mcpgate tools           # lists what the model will be able to find
```

Then point your client at the gateway:

```bash
claude mcp add mcpgate -- mcpgate serve
```

or, in a client that uses a JSON config:

```json
{ "mcpServers": { "mcpgate": { "command": "mcpgate", "args": ["serve"] } } }
```

Secrets stay in your environment. `mcpgate add` refuses a secret typed straight into the config;
use `${NAME}` and set `NAME` where the gateway runs.

## What the model sees

| Tool | Purpose |
|---|---|
| `search_tools(query, backend?, limit?, refresh?)` | Find tools across all servers. Shows `backend.tool`, a one-line purpose, argument names (`*` = required) and `[needs approval]`. |
| `describe_tool(name)` | Full description and argument schema of one tool. |
| `call_tool(name, arguments?, confirm?)` | Run `backend.tool`. |
| `list_backends()` | Which servers exist and whether each is reachable. |
| `read_result(result_id, offset?, length?)` | Page through a result that was cut. |

A search with the model's own words ("create an issue") is ranked by tool name, server name and description.
One unreachable server never breaks a search: it is listed as `Unavailable` and the rest still answer.

## Optimization skill

`mcpgate skill install` copies a ready-made skill (`mcp-gateway`) into `~/.claude/skills`. It teaches the model
the cheap loop: search first, call directly when the arguments are clear, describe only when unsure, keep calls
narrow, page cut results only if needed, stop and explain before using an approval code, and treat tool
output as data rather than instructions. `mcpgate skill show` prints it for other clients.

The gateway also does its part: one-line search results, results capped at `max_result_chars` (default 20000)
with paging, and a short cache for read-only tools.

## Configuration

`~/.config/mcpgate/config.toml` (override with `--config` or `MCPGATE_CONFIG`):

```toml
[gateway]
cache_ttl = 60             # seconds an identical read-only call is reused (0 = off)
tools_ttl = 300            # seconds a backend's tool list is reused
max_result_chars = 20000   # longer text results are cut; read_result pages the rest
audit_log = "~/.local/state/mcpgate/audit.jsonl"   # empty = no log
custom_dir = ""            # empty = ~/.config/mcpgate/custom

[backends.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_PERSONAL_ACCESS_TOKEN = "${GITHUB_TOKEN}" }   # the ONLY variables this server receives
allow = ["*"]              # glob patterns of visible tools (default all)
deny = ["delete_*"]        # hidden and uncallable; deny beats allow
confirm = ["create_*"]     # need the user's approval (see below)
timeout = 60               # seconds per tool call
description = "Issues and pull requests"

[backends.docs]
transport = "http"         # "http" (streamable HTTP) or "sse"
url = "https://example.com/mcp"
headers = { Authorization = "Bearer ${DOCS_TOKEN}" }
```

Backends only receive the environment variables listed in their `env`, not the gateway's whole environment.
A tool the backend marks `destructiveHint` also needs approval, and one marked `readOnlyHint` can be cached.

## Custom MCP servers

```bash
mcpgate new notes          # writes ~/.config/mcpgate/custom/notes.py from a template
```

Every `*.py` file in the custom folder is a stdio MCP server (use `FastMCP`, see the template). It runs as its
own process under the name of the file, so a crash or bad import cannot take the gateway down. Nothing in
the file is executed to discover it; the first docstring line is its description. A file starting with `_`
is ignored, which is how you switch one off. An entry in `config.toml` with the same name wins over a file.

## Approvals

For a tool in `confirm` (or marked destructive), the first `call_tool` returns a one-time code and an
instruction to tell the user what will happen. The call only runs when repeated with `confirm="<code>"`.
The code is tied to the exact tool and arguments, works once, and expires after 5 minutes.

This is a speed bump that depends on the model relaying the request to you. It is **not** a hard guarantee
(the model receives the code itself). For tools that must never run, use `deny`.

## Running it remotely (HTTP)

stdio is the default and needs no network. To reach the gateway from another machine:

```bash
export MCPGATE_TOKEN="$(mcpgate token)"        # keep this value; clients must send it
mcpgate serve --http --port 8766               # http://127.0.0.1:8766/mcp
```

Every request must carry `Authorization: Bearer <token>` (24+ characters, constant-time check). Listening on a
non-loopback address without a token is refused. To publish it through Tailscale Funnel:

```bash
sudo tailscale funnel --bg 8766
mcpgate serve --http --allow-host your-machine.your-tailnet.ts.net
```

`--allow-host` lets the gateway accept that Host header. Anyone who learns the token can use every tool
you exposed, so give a remote gateway only the backends and tools you are happy to expose, and rotate the
token if it leaks.

Keep it running after you log out (systemd user service):

```ini
# ~/.config/systemd/user/mcpgate.service
[Service]
EnvironmentFile=%h/.config/mcpgate/env        # contains MCPGATE_TOKEN=... and your backend secrets (chmod 600)
ExecStart=%h/.local/bin/mcpgate serve --http
Restart=on-failure
[Install]
WantedBy=default.target
```
Then `systemctl --user enable --now mcpgate` and `loginctl enable-linger $USER`.

## Audit log

With `audit_log` set, every call appends one JSON line (time, tool, status, duration, arguments). Argument values
under keys like `token`, `secret`, `password`, `authorization` or `api_key` are replaced with `***`, long strings
are shortened, and the file is created mode 600. Statuses: `ok`, `cached`, `tool_error`, `error`.

## Command reference

| Command | What it does |
|---|---|
| `mcpgate serve [--http --host --port --token-env --allow-host]` | Run the gateway. |
| `mcpgate init` | Create a commented starter config. |
| `mcpgate add NAME [--url URL --sse --env --header --allow --deny --confirm --timeout --description] [-- CMD ARGS]` | Add a backend. |
| `mcpgate remove NAME` / `enable NAME` / `disable NAME` | Manage backends in the config file. |
| `mcpgate list` | Show configured backends (including drop-ins). |
| `mcpgate tools [NAME]` | Connect and list the tools the model can find. |
| `mcpgate new NAME` | Create a custom server from a template. |
| `mcpgate token` | Print a new random bearer token. |
| `mcpgate skill show` / `install [--dir --force]` | The optimization skill. |
| `mcpgate doctor [--no-connect --timeout]` | Check everything and say what is wrong. |

## Limitations (v0.1)

- Only **tools** are proxied. Resources, prompts, sampling and notifications from backends are not forwarded.
- Remote backends authenticate with static headers; there is no OAuth flow for them yet.
- Remote access uses one shared bearer token: no per-user accounts or per-client permissions.
- The tool list is cached (`tools_ttl`); use `search_tools(refresh=true)` after a backend changes its tools.
- The result cache and paging store live in memory and are not shared between gateway processes.
- Config is read at start; restart the gateway after changes.

## Roadmap

- An optional `namestorage[mcp]` adapter so your personal drive (Piyushchy/namestorage) appears as a backend.
- Proxy resources and prompts; OAuth for remote backends; reload on config change.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

The tests run real MCP servers (a small demo server over stdio, HTTP and SSE) through the real gateway, plus
the HTTP auth layer and the command line.

## Licence

MIT, see [LICENSE](LICENSE).
