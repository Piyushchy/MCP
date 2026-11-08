"""A tiny MCP server used by the tests as a stand-in backend (stdio)."""
import os
import sys

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

READ = ToolAnnotations(readOnlyHint=True)
mcp = FastMCP("demo")


@mcp.tool(annotations=READ)
def echo(text: str) -> str:
    """Echo the text back. Useful to check that routing works."""
    return text


@mcp.tool(annotations=READ)
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


@mcp.tool(annotations=READ)
def counter() -> int:
    """Return how many times this process has been asked (shows caching)."""
    counter.n = getattr(counter, "n", 0) + 1
    return counter.n


@mcp.tool(annotations=READ)
def big(n: int) -> str:
    """Return n characters."""
    return "x" * n


@mcp.tool(annotations=READ)
def whoami() -> str:
    """Return the DEMO_SECRET environment variable and whether HOME-like variables leaked."""
    return f"secret={os.environ.get('DEMO_SECRET', '-')} leak={os.environ.get('GATEWAY_ONLY', '-')}"


@mcp.tool()
async def nap(seconds: float) -> str:
    """Wait, then answer (used to test reloads during a running call)."""
    import asyncio
    await asyncio.sleep(seconds)
    return "rested"


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
def wipe(target: str) -> str:
    """Delete everything in the target. Dangerous."""
    return f"wiped {target}"


@mcp.tool()
def create_note(title: str) -> str:
    """Create a note."""
    return f"created {title}"


@mcp.tool()
def delete_note(title: str) -> str:
    """Delete a note."""
    return f"deleted {title}"


@mcp.tool()
def explode() -> str:
    """Always fails."""
    raise RuntimeError("boom")


@mcp.tool()
def die() -> str:
    """Kill this server process (used to test restarts)."""
    sys.stdout.flush()
    os._exit(3)


if __name__ == "__main__":
    # python demo_server.py                      -> stdio
    # python demo_server.py streamable-http PORT -> HTTP (also: sse)
    if len(sys.argv) > 2:
        mcp.settings.port = int(sys.argv[2])
        mcp.run(sys.argv[1])
    else:
        mcp.run("stdio")
