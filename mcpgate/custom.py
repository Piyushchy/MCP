"""Custom MCP servers as drop-in files.

Every ``*.py`` file in the custom folder is a stdio MCP server. The gateway runs it as its
own process (so a crash or a bad import cannot take the gateway down) and registers it as a
backend named after the file. Nothing in the file is executed to discover it.
"""
from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

from .config import NAME_RE, Backend, Settings

TEMPLATE = '''\
"""{name}: describe what this server is for in one line."""
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("{name}")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def hello(who: str = "world") -> str:
    """Say hello. Mark tools that only read with readOnlyHint so the gateway can cache them."""
    return f"hello {{who}}"


if __name__ == "__main__":
    mcp.run("stdio")
'''


def default_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "mcpgate" / "custom"


def folder(settings: Settings) -> Path:
    return Path(settings.custom_dir).expanduser() if settings.custom_dir else default_dir()


def slug(stem: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", stem.lower()).strip("-_")[:32]


def _doc_line(path: Path) -> str:
    try:
        doc = ast.get_docstring(ast.parse(path.read_text()))
    except (SyntaxError, OSError, ValueError):
        return ""
    return doc.strip().splitlines()[0] if doc else ""


def discover(directory: Path) -> dict[str, Backend]:
    found: dict[str, Backend] = {}
    if not directory.is_dir():
        return found
    for f in sorted(directory.glob("*.py")):
        if f.name.startswith(("_", ".")) or not f.is_file():
            continue
        name = slug(f.stem)
        if not NAME_RE.match(name):
            continue
        found[name] = Backend(name=name, transport="stdio", command=sys.executable, args=[str(f)],
                              cwd=str(directory), description=_doc_line(f), source="custom")
    return found


def with_custom(settings: Settings) -> Settings:
    """Add drop-in servers to the settings. An entry in the config file wins over a file of the same name."""
    for name, b in discover(folder(settings)).items():
        settings.backends.setdefault(name, b)
    return settings


def scaffold(settings: Settings, name: str) -> Path:
    name = slug(name)
    if not NAME_RE.match(name):
        raise ValueError("name must be lowercase letters, digits, '-' or '_'")
    d = folder(settings)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{name}.py"
    if path.exists():
        raise FileExistsError(str(path))
    path.write_text(TEMPLATE.format(name=name))
    return path
