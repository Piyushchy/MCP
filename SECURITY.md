# Security

mcpgate sits between your AI apps and the tools they can use, and it holds the tokens for those tools. This page
says what it promises, what it does not, and how to report a problem. The full analysis is in
[docs/threat-model.md](docs/threat-model.md).

## Reporting a vulnerability

Please report privately, not in a public issue:

- GitHub: **Security → Report a vulnerability** on https://github.com/Piyushchy/MCP (private advisory), or
- email mail@piyushchy.is-a.dev with "mcpgate security" in the subject.

Include what you did, what you expected and what happened. You will get an answer within a few days. Fixes are
released as soon as they are ready, and you are credited if you like.

## The rules the admin page follows

Each rule has tests that fail the build if it is broken (`tests/test_security.py` and the files named below).

| # | Rule | Proved by |
|---|------|-----------|
| 1 | The admin page listens on `127.0.0.1` only. No setting, flag or environment variable changes that, and if the port is busy it does not start elsewhere. | `test_the_admin_bind_address_cannot_be_configured`, `test_binding_somewhere_else_is_not_an_option…`, `test_admin_service.py` |
| 2 | The public listener (the one a tunnel points at) contains no admin code: every admin path is 404 there, with or without a token, and the public modules never import the admin package. | `test_every_admin_path_is_absent_from_the_public_listener`, `test_the_public_modules_do_not_import_the_admin_code` |
| 3 | Secrets are write-only. A stored secret is never sent back to the browser, never written to the log, audit file, errors or `doctor` output. Passphrases and tokens are stored as hashes; a new token is shown once. | `test_a_canary_secret_never_appears_anywhere_it_could_be_read`, `test_doctor_never_prints_a_stored_secret`, `test_secretstore.py`, `test_admin_audit.py` |
| 4 | Every state-changing request needs a signed-in session **and** a CSRF token **and** a matching `Origin`. A wrong `Host`, or any proxy header (`X-Forwarded-*`, `Forwarded`, `Via`, `CF-*`, `Tailscale-*`), is refused on every route. Sessions are HttpOnly, SameSite=Strict, get a new id at login, expire when idle (30 min) and after 8 h, and end when the passphrase changes. | `test_route_table_has_no_unprotected_route…`, `test_every_route_refuses_the_wrong_caller`, `test_without_a_session_nothing_is_served…`, `test_a_session_id_set_by_an_attacker_is_never_adopted`, `test_admin_auth.py` |
| 5 | Anything that can run code on this computer or open access from outside needs the admin passphrase typed again (valid 5 minutes): enabling a program backend, adding a custom command, turning on custom commands, changing the sign-in passphrase, creating a token, restarting. Custom commands are on by default because the passphrase is asked each time; they can be switched off in Settings. | `test_every_action_that_can_run_code_or_open_access_needs_the_passphrase_again` |
| 6 | Strict Content-Security-Policy (`default-src 'none'`, scripts only from the page's own file, no inline script, no `eval`, no CDN), `frame-ancestors 'none'`, `nosniff`, `no-store`. The page builds everything with `textContent`; nothing a backend, app or log can say is ever treated as HTML. | `test_content_security_policy_and_frontend_sinks`, `test_hostile_values_come_back_only_as_json_data`, `test_security_browser.py` (real Chromium) |
| 7 | Files that hold secrets or hashes (`config.toml`, `secrets.json`, `auth.json`, `oauth.json`, the audit log and its rotations) are mode 600 and written atomically; their folder is mode 700. Group- or world-readable secret and auth files are refused, and `mcpgate doctor` flags every one. | `test_every_file_that_holds_a_secret_or_a_hash_is_owner_only`, `test_group_readable_secret_and_auth_files_are_refused`, `test_doctor_flags_every_private_file…` |
| 8 | Every endpoint ships with tests, including the failing cases (no session, no CSRF, wrong Origin, wrong Host). A route added without a session and CSRF check fails the build. | `test_route_table_has_no_unprotected_route…` and the per-feature `test_admin_*.py` files |

## What mcpgate does not protect against

Be aware of these; they are choices or limits, not bugs:

- **Anyone who can already act as you on the computer.** Malware or another program running as your user can read
  your files, including `secrets.json`. Secrets are stored in plain text, protected by file permissions and a
  private folder, not encrypted: encryption would need a key stored next to them or a passphrase typed at every
  start, which a background service cannot do.
- **Other users on the same computer** can open the loopback port but cannot sign in without the passphrase; sign-in
  attempts are rate limited. They cannot read your files unless the permissions were changed (`mcpgate doctor` checks).
- **A backend you configured sees the secrets you gave it** (that is what they are for) and can return them in a
  tool result. mcpgate blanks stored secrets from its own errors and logs, but passes a backend's results on to the
  model unchanged. Only add backends you trust, and give each one a token with the least permission it needs.
- **A model can be tricked** (prompt injection) into asking for harmful tool calls. The defences are the ones you set:
  `deny` and `confirm` rules per backend, and the Approvals inbox where you decide, seeing the exact arguments. The
  inbox protects the long-running service; a gateway started directly by an app over stdio uses the older
  confirm-code prompt.
- **Whoever holds your sign-in passphrase or access token** can use your tools through the public address. Use a long
  passphrase and remove tokens you no longer need.

## Safe defaults

Nothing is reachable from the network until you set up remote access. Custom commands are off. Destructive tools
need approval. Remote access refuses to be pointed at private or local addresses when you test it. The installer
asks for no secrets and opens no port beyond the loopback ones.
