# Threat model

## What is being protected

| Asset | Where it lives | Why it matters |
|---|---|---|
| Backend tokens and keys | `secrets.json` (mode 600) or environment variables | They let whoever holds them act as you on GitHub, Notion, etc. |
| Admin passphrase, sign-in passphrase, access token | hashes only, in `auth.json` (mode 600) | They control the admin page and remote access |
| Logins to backends that need an account | `backend_oauth.json` (mode 600), written atomically, never sent to the page or logged | They let whoever holds them act as you on that service |
| Signed-in apps | hashed tokens in `oauth.json` (mode 600) | They let claude.ai call your tools |
| Your computer | the programs that stdio backends run | A custom command is code that runs as you |
| The record of what happened | `audit.jsonl`, rotated, mode 600 | You need it to be complete and free of secrets |

## Parts and trust boundaries

```
 browser ──(loopback)──▶ [ admin page  127.0.0.1:8767 ]  ┐
                                                          ├─ one process: the hub (config, secrets, backends)
 claude.ai ─▶ tunnel ─▶ [ public listener 127.0.0.1:8766 ]┘
 local app ──(stdio)──▶ mcpgate serve
                                      hub ──▶ backends (programs or remote servers)
```

- The **admin page** trusts only a person at this computer who knows the admin passphrase.
- The **public listener** trusts only callers with a valid access token or a sign-in made with the sign-in passphrase.
  It serves the MCP endpoint and the OAuth endpoints and nothing else. The admin code is not mounted on it.
- **The project site on the public address** (`site = true`, the default). `GET` and `HEAD` for `/` and `/assets/...` answer
  with files shipped inside the package; nothing is fetched and nothing a visitor sends is used except to pick one of those
  files (traversal-style paths are refused). The page is served with a policy that allows no inline script and no outside
  loads. It shares an origin with `/consent`, so a change to the site's script would be a change to code that runs next to the
  sign-in page: the site's files are reviewed and shipped with mcpgate like any other code, and `site = false` removes it.
- **`GET /oauth/callback`** on the admin listener is the one admin route without a session: your browser arrives there
  from another site's login page. It accepts only the one-time `state` of a sign-in you started from the admin page (valid
  for five minutes, used once) and answers 400 to anything else. It is loopback-only like the rest. You can only sign in to
  servers you added yourself, and the server's sign-in addresses must be https.
- **Backends** are semi-trusted: they get the secrets configured for them and their output is untrusted data.
- **The model** is untrusted: it may be manipulated by text in tool results, web pages or documents.

## Threats and what answers them

| Threat | Answer | Test |
|---|---|---|
| Someone on the network reaches the admin page | Bound to 127.0.0.1, fixed in code, no fallback address | `test_the_admin_bind_address_cannot_be_configured` |
| A tunnel or reverse proxy accidentally forwards the admin page | Requests with proxy headers or a foreign `Host` are refused on every route; the public listener has no admin code at all | `test_every_route_refuses_the_wrong_caller`, `test_every_admin_path_is_absent_from_the_public_listener` |
| DNS rebinding: a web page makes your browser talk to 127.0.0.1 under another name | `Host` must be exactly `127.0.0.1:<port>` or `localhost:<port>`; state changes also need `Origin` | same |
| CSRF from another site | SameSite=Strict cookie, per-session token in a header, `Origin` check | `test_every_route_refuses_the_wrong_caller` |
| Session fixation or theft | New id at login, HttpOnly cookie, idle and absolute expiry, ended by passphrase change | `test_a_session_id_set_by_an_attacker_is_never_adopted`, `test_passphrase_change_and_logout_end_old_sessions` |
| Guessing the passphrase | scrypt hashes, rising delays after failures, one-time setup code that expires and works once | `test_admin_auth.py` |
| Cross-site scripting through a name or text a backend, app or log can supply | CSP without inline script, `textContent` only, JSON responses with `nosniff`, escaped consent page | `test_content_security_policy_and_frontend_sinks`, `test_security_browser.py` |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` on the admin page and the consent page | `test_every_route_refuses_the_wrong_caller`, `test_the_consent_page_escapes…` |
| Someone with a stolen browser session turns on code execution | Step-up: the passphrase again for every action that can run code or open access; each program asks for the passphrase again, and custom commands can be switched off in Settings | `test_every_action_that_can_run_code_or_open_access_needs_the_passphrase_again` |
| A secret leaks through the page, the log or an error | Secrets are write-only; the audit log blanks stored values and masks secret-looking arguments; `doctor` shows names and where they resolve, never values | `test_a_canary_secret_never_appears_anywhere_it_could_be_read`, `test_doctor_never_prints_a_stored_secret` |
| Reading secrets off disk as another user | Mode 600 files in a mode 700 folder; group- or world-readable secret files are refused to load; `doctor` flags them | `test_every_file_that_holds_a_secret_or_a_hash_is_owner_only` |
| The connection check is used to probe your network (SSRF) | It only contacts the saved public address, only over https, only to public (or Tailscale) addresses, no redirects, short timeout, size cap, rate limit | `tests/test_remote.py`, `tests/test_admin_remote.py` |
| The model is manipulated into a destructive call | `deny`/`confirm` rules, destructive tools always need approval, exact arguments shown in the Approvals inbox, the model never receives an approval code | `tests/test_approvals.py`, `tests/test_admin_approvals.py` |
| A signed-in app is no longer wanted | Sign out one session or everything, remove the app; takes effect on the running gateway at once | `tests/test_admin_remote.py` |
| The installer does something surprising | Never asks for or stores secrets, refuses root, opens no port, removes only directories named `mcpgate` when purging | `tests/test_install_sh.py`, `tests/test_service.py` |

## Not covered (by design)

See "What mcpgate does not protect against" in [SECURITY.md](../SECURITY.md): malware running as you, unencrypted
secrets at rest, a trusted backend returning a secret it was given, and the older confirm-code prompt for gateways
that an app starts directly over stdio.

## Keeping it true

`tests/test_security.py` fails if someone adds an admin route that is open to anyone, adds a way to bind the admin
page elsewhere, puts an inline script or an HTML-injecting call into the page, or leaves a secret file readable by
others. When you add a feature, add its failing-case tests next to it (see the helpers in `tests/admin_helpers.py`).
