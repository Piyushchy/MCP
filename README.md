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
# GitHub's own hosted MCP server: no local process, just your token in a header.
# Make a fine-grained token limited to the repos you want, and put it in your environment first.
export GITHUB_TOKEN=...
mcpgate add github --url https://api.githubcopilot.com/mcp/ \
    --header 'Authorization=Bearer ${GITHUB_TOKEN}' --deny 'delete_*'

# a local server started as a command (everything after -- is the command)
mcpgate add colab --start-timeout 120 -- uvx git+https://github.com/googlecolab/colab-mcp

mcpgate doctor          # checks the config, commands, environment variables and live connections
mcpgate tools           # lists what the model will be able to find
mcpgate tools github    # one backend; use it to pick the exact tool names for --confirm / --deny
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

[backends.notes_server]
command = "npx"
args = ["-y", "some-mcp-server-package"]
env = { SOME_TOKEN = "${SOME_TOKEN}" }   # the ONLY variables this server receives
allow = ["*"]              # glob patterns of visible tools (default all)
deny = ["delete_*"]        # hidden and uncallable; deny beats allow
confirm = ["create_*"]     # need the user's approval (see below)
timeout = 60               # seconds per tool call
start_timeout = 30         # seconds for the server to start (raise it for a first npx/uvx download)
description = "What this server is for"

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

## Using it from claude.ai (HTTPS + OAuth)

claude.ai (web and phone) runs on Anthropic's servers, so it cannot start a program on your laptop. It needs a
public HTTPS address, and it logs in with OAuth. mcpgate includes a small single-owner OAuth server for this.
(If you only use Claude Code or Claude Desktop on the same computer, skip this section: stdio needs no network.)

```bash
export MCPGATE_PASSPHRASE="$(mcpgate token)"     # you type this on the approval page. Save it somewhere safe.
sudo tailscale funnel --bg 8766                  # gives you https://your-machine.your-tailnet.ts.net
mcpgate serve --http --port 8766 \
    --public-url https://your-machine.your-tailnet.ts.net \
    --allow-host your-machine.your-tailnet.ts.net
```

Then in claude.ai: **Customize > Connectors > Add custom connector**, enter
`https://your-machine.your-tailnet.ts.net/mcp`, leave the OAuth client fields empty (if asked how Claude
identifies itself, choose **Register automatically**), and click **Connect**. Your browser opens the gateway's
approval page; type the passphrase and press **Approve**. From then on Claude holds short-lived tokens and
you do not sign in again (they refresh by themselves, and survive a gateway restart).

**Funnel when you already use it for something else.** Funnel offers three public ports (443, 8443, 10000).
If one is taken (say 443), use another for the gateway: `sudo tailscale funnel --bg --https=8443 8766`, and use
`https://your-machine.your-tailnet.ts.net:8443` as `--public-url` (keep `--allow-host` as the bare host name).
`tailscale funnel status` lists what is published. A shared address with the gateway under a path does not
work, because the OAuth discovery addresses must be at the root.

**Cloudflare Tunnel instead.** It works too (point it at `http://127.0.0.1:8766`). One warning: do not turn on a
captcha, "I'm under attack" or bot protection for the whole address. claude.ai's servers make the MCP and token
requests and cannot solve a captcha, and Anthropic's docs warn that a WAF in front of the connection can break
sign-in. A challenge on the human-only `/consent` path would be fine, but is not built in yet. Cloudflare's 100 MB
request limit does not matter here: MCP requests are small JSON, and results are capped at `max_result_chars`.
Requests that wait over 100 seconds for a reply get a 524, so keep tool calls under that.

How it protects you:

- **Only you can approve.** Approval needs the passphrase (12+ characters, from the environment, never stored).
  Five wrong guesses lock the page for 1 minute, then 2, 4... up to 15. A stranger who spams guesses can
  therefore delay your own approval for a few minutes, but cannot get in.
- **Redirect allow-list.** Only `claude.ai` and `localhost` (Claude Code) may register as an app. Others are
  refused at registration. Add one with `--oauth-redirect-host HOST`.
- **Short tokens, hashed at rest.** Access tokens last 1 hour; refresh tokens 30 days and rotate on every use
  (a reused one is rejected). The state file (`~/.local/state/mcpgate/oauth.json`, mode 600) holds only hashes
  of tokens, so a leaked copy cannot call your gateway.
- **Sign everyone out:** `mcpgate oauth revoke-all` (works on a running gateway). `mcpgate oauth status` shows what is signed in.
- The approval page cannot be framed, is never cached, and escapes everything an app tells it.

What this does **not** do: there is one owner and one passphrase. Everyone who passes the approval page, or
holds a token, can use every backend and tool you left enabled, as you. For a gateway on the internet, give it
only the backends and tools you are happy to expose (`allow`/`deny`, or a separate `--config` file).

Tested: the whole flow (registration, passphrase approval, PKCE, token use, refresh rotation and replay,
expiry, revocation, lockout, restart) runs against a live server in the test suite, and the discovery
documents follow what Anthropic's connector docs ask for. **Not yet tested against the real claude.ai.** If
connecting fails, run `mcpgate serve` in a terminal and watch for the request that fails; `Couldn't reach the
MCP server` usually means the public address or `--allow-host` is wrong. claude.ai prefers
"Client ID Metadata Documents", which mcpgate does not offer; Anthropic documents that it falls back to
dynamic registration, which mcpgate does.

### A fixed token instead (no OAuth)

Some clients (and some claude.ai organizations that have the "Request headers" beta) can send a fixed header.

```bash
export MCPGATE_TOKEN="$(mcpgate token)"
mcpgate serve --http --port 8766 --allow-host your-machine.your-tailnet.ts.net
```

Every request must then carry `Authorization: Bearer <token>` (24+ characters, constant-time check). In
claude.ai the header value must include the word: `Bearer your-token`. Listening on a non-loopback address
with neither a token nor OAuth is refused. You can set both: the token keeps working next to OAuth.
Anyone who learns the token can use every exposed tool, so rotate it if it leaks.

### Keep it running after you log out

```ini
# ~/.config/systemd/user/mcpgate.service
[Service]
EnvironmentFile=%h/.config/mcpgate/env        # MCPGATE_PASSPHRASE=... and your backend secrets (chmod 600)
ExecStart=%h/.local/bin/mcpgate serve --http --port 8766 --public-url https://your-machine.your-tailnet.ts.net --allow-host your-machine.your-tailnet.ts.net
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
| `mcpgate serve [--http --host --port --token-env --allow-host --public-url --passphrase-env --state-file --oauth-redirect-host]` | Run the gateway. `--public-url` turns on OAuth. |
| `mcpgate oauth status` / `revoke-all` | See or sign out the apps connected through OAuth. |
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
- Remote *backends* authenticate with static headers; the gateway cannot yet sign in to a backend that requires OAuth.
- Remote access has one owner: one passphrase, one static token. No per-user accounts or per-client permissions.
- OAuth is implemented but not yet verified against the real claude.ai (see the section above).
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
