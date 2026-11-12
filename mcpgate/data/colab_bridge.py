"""colab-mcp, made usable when your browser is on a different computer than mcpgate.

Not meant to be run by hand: `mcpgate bridge colab` starts it inside colab-mcp's own (cached) environment.

colab-mcp opens a WebSocket on a random localhost port with a random token and runs `webbrowser.open` on the machine
it runs on. The Colab page in your browser must connect to that port, which cannot work when mcpgate is on a server.
This changes only three things: the port is fixed (COLAB_MCP_PORT, default 8799) so it can be forwarded, the token is
kept in a mode-600 file so the link stays the same across restarts, and the connect tool *returns* the link (and the
steps to use it) instead of opening a browser nobody is looking at.
"""
import os
import secrets
import sys
from pathlib import Path

import websockets
from mcp.types import TextContent
from fastmcp.tools.tool import ToolResult
from websockets.typing import Subprotocol

import colab_mcp.session as session
import colab_mcp.websocket_server as wss_mod

PORT = int(os.environ.get("COLAB_MCP_PORT", "8799"))
STATE = Path(os.environ.get("COLAB_MCP_STATE") or Path(os.environ.get("XDG_STATE_HOME") or "~/.local/state").expanduser() / "mcpgate")
LINK = {"url": ""}


def _token() -> str:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    f = STATE / "colab-token"
    if f.exists() and f.read_text().strip():
        return f.read_text().strip()
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


def _remember_link(url: str):
    LINK["url"] = url
    (STATE / "colab-connect-url.txt").write_text(url + "\n")
    return True


HELP = ("Not connected yet. Tell the user to do this, then call this tool again:\n"
        "1. If mcpgate runs on another computer, on the computer with their browser run: ssh -L {port}:127.0.0.1:{port} USER@THE-SERVER\n"
        "2. Open this link in that same browser, signed in to Google, and keep the tab open:\n   {url}")


class RemoteFriendlyMiddleware(session.ColabProxyMiddleware):
    async def on_call_tool(self, context, call_next):
        result = await super().on_call_tool(context, call_next)
        if context.message.name == session.INJECTED_TOOL_NAME and not self.proxy_client.is_connected() and LINK["url"]:
            return ToolResult(content=[TextContent(type="text", text=HELP.format(port=PORT, url=LINK["url"]))],
                              structured_content={"result": False})
        return result


session.webbrowser.open_new = lambda url, *a, **k: _remember_link(url)
session.ColabWebSocketServer = FixedServer
session.ColabProxyMiddleware = RemoteFriendlyMiddleware
# answer a little before a typical 60 s client timeout, so the user gets the link instead of an error
session.UI_CONNECTION_TIMEOUT = float(os.environ.get("COLAB_MCP_WAIT", "40"))

from colab_mcp import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
