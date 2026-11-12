"""Run Google's colab-mcp on a computer that is not the one your browser is on.

colab-mcp opens a WebSocket on a random localhost port with a random token and then runs `webbrowser.open` on the
machine it runs on. The Colab page in *your* browser must connect to that port, so when mcpgate runs on another
computer (a server, a laptop you reach over SSH) the tab never connects and the connect tool times out.

This wrapper changes only three things:
  * the port is fixed (COLAB_MCP_PORT, default 8799), so you can forward it
  * the token is kept in a file (mode 600) instead of being random each start, so the link does not change
  * instead of opening a browser, the connect link is written to <state dir>/colab-connect-url.txt

Use it as the backend command:   python /path/to/colab_mcp_remote.py
(with colab-mcp installed in that Python: pip install git+https://github.com/googlecolab/colab-mcp)
"""
import os
import secrets
import sys
from pathlib import Path

import websockets
from websockets.typing import Subprotocol

import colab_mcp.session as session
import colab_mcp.websocket_server as wss_mod

PORT = int(os.environ.get("COLAB_MCP_PORT", "8799"))
STATE = Path(os.environ.get("COLAB_MCP_STATE", Path.home() / ".local" / "state" / "mcpgate"))


def _token() -> str:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    f = STATE / "colab-token"
    if f.exists():
        t = f.read_text().strip()
        if t:
            return t
    t = secrets.token_urlsafe(16)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as h:
        h.write(t)
    return t


class FixedServer(wss_mod.ColabWebSocketServer):
    def __init__(self, host="localhost"):
        super().__init__(host)
        self.token = _token()

    async def __aenter__(self):
        self._server = await websockets.serve(
            self._connection_handler, host=self.host, port=PORT, subprotocols=[Subprotocol("mcp")],
            origins=self.allowed_origins, process_request=self._validate_authorization)
        self.port = self._server.sockets[0].getsockname()[1]
        return self


def _write_link(url: str) -> None:
    (STATE / "colab-connect-url.txt").write_text(url + "\n")
    print("colab-mcp: open this link in the browser you use for Colab:\n  " + url, file=sys.stderr, flush=True)


# Same link colab-mcp would have opened, written to a file instead
session.webbrowser.open_new = lambda url, *a, **k: _write_link(url) or True
session.ColabWebSocketServer = FixedServer
# Give up a little before a typical 60 s client timeout so the tool answers false instead of the call failing
session.UI_CONNECTION_TIMEOUT = float(os.environ.get("COLAB_MCP_WAIT", "45"))

from colab_mcp import main  # noqa: E402

if __name__ == "__main__":
    main()
