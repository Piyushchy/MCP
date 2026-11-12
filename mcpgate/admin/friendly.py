"""Turn the raw reason a backend failed into something a person can act on."""
from __future__ import annotations

import re


def leaves(e: BaseException) -> list[BaseException]:
    if isinstance(e, BaseExceptionGroup):
        return [x for sub in e.exceptions for x in leaves(sub)]
    return [e]


def _status(text: str, leaf_list: list[BaseException]) -> int | None:
    for x in leaf_list:
        r = getattr(x, "response", None)
        code = getattr(r, "status_code", None)
        if isinstance(code, int):
            return code
    m = re.search(r"\b(401|403|404|405|429|50[0-4])\b", text)
    return int(m.group(1)) if m else None


def explain(err, command: str = "") -> tuple[str, str]:
    """(what went wrong, what to try). ``err`` is an exception or the text of one."""
    found = leaves(err) if isinstance(err, BaseException) else []
    text = " ".join([str(err)] + [f"{type(x).__name__} {x}" for x in found]).lower()
    name = f"“{command}”" if command else "the program"

    if any(isinstance(x, FileNotFoundError) for x in found) or "no such file or directory" in text or "command not found" in text:
        return (f"{name} was not found on this computer.",
                "Install it first (for example uv for uvx, or Node.js for npx), or check how the command is spelled.")
    if any(isinstance(x, PermissionError) for x in found) or "permission denied" in text:
        return f"This computer would not let mcpgate run {name} (permission denied).", "Check that the file is executable and that you own it."
    if "sign-in needed" in text or any(type(x).__name__ == "SignInRequired" for x in found):
        return "This server needs you to sign in.", "Open Backends, find this server and press Sign in."
    code = _status(text, found)
    if code == 401:
        return "The server did not accept the token (401 Unauthorized).", "Check that the token is correct, has not expired, and was pasted in full. You can enter it again."
    if code == 403:
        return "The server understood the token but refused access (403 Forbidden).", "The token probably lacks the permissions this server needs. Create one with the right scopes."
    if "session terminated" in text:     # how the MCP client library reports a 404 from the server
        code = 404
    if code in (404, 405):
        return f"Nothing was found at that address ({code}).", "The address is probably wrong. Check the whole address, including the path (many servers end in /mcp)."
    if code == 429:
        return "The server says you are sending too many requests (429).", "Wait a minute and test again."
    if code and code >= 500:
        return f"The server had a problem of its own ({code}).", "Try again in a little while."
    if any(k in text for k in ("name or service not known", "nodename nor servname", "getaddrinfo", "temporary failure in name resolution", "no address associated")):
        return "That host name could not be found.", "Check the address for typos, and that this computer is online."
    if "connection refused" in text or "connecterror" in text or "all connection attempts failed" in text:
        return "Nothing answered at that address.", "Check the address and port, and that the server is running."
    if "certificate" in text or "ssl" in text:
        return "The secure connection failed (certificate problem).", "Use the exact https address the server gave you."
    if "timeout" in text or "timed out" in text or "did not answer" in text:
        return "The server did not answer in time.", "It may still be starting up (the first start can download things). Try again, or give it more time when adding it."
    if "closed" in text or "eof" in text or "exited" in text or "broken pipe" in text:
        return f"{name.capitalize()} started but stopped straight away.", "Run it in a terminal to see its own error. It often needs a secret or a setting that is missing."
    return "", ""
