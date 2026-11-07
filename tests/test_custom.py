import sys

import pytest
from mcp.shared.memory import create_connected_server_and_client_session as connect

from mcpgate import custom, server
from mcpgate.config import Backend, Settings


def test_discover_finds_py_files_and_reads_docstring_without_running_them(tmp_path):
    (tmp_path / "notes.py").write_text('"""Personal notes server.\n\nMore."""\nraise SystemExit("must not run")\n')
    (tmp_path / "My Tools.py").write_text("x = 1\n")
    (tmp_path / "_private.py").write_text("x = 1\n")
    (tmp_path / "readme.txt").write_text("not python")
    (tmp_path / "broken.py").write_text("def (:\n")
    found = custom.discover(tmp_path)
    assert set(found) == {"notes", "my-tools", "broken"}
    b = found["notes"]
    assert b.source == "custom" and b.command == sys.executable and b.args == [str(tmp_path / "notes.py")]
    assert b.description == "Personal notes server."
    assert found["broken"].description == ""


def test_missing_folder_is_fine(tmp_path):
    assert custom.discover(tmp_path / "nope") == {}


def test_config_entry_wins_over_a_file_of_the_same_name(tmp_path):
    (tmp_path / "notes.py").write_text("x = 1\n")
    s = Settings(custom_dir=str(tmp_path))
    s.backends["notes"] = Backend(name="notes", command="other")
    assert custom.with_custom(s).backends["notes"].command == "other"


def test_scaffold_creates_a_working_template_and_refuses_to_overwrite(tmp_path):
    s = Settings(custom_dir=str(tmp_path))
    p = custom.scaffold(s, "My Notes")
    assert p.name == "my-notes.py" and "FastMCP" in p.read_text()
    with pytest.raises(FileExistsError):
        custom.scaffold(s, "my notes")
    with pytest.raises(ValueError):
        custom.scaffold(s, "!!!")


async def test_a_scaffolded_server_works_through_the_gateway(tmp_path):
    s = Settings(custom_dir=str(tmp_path))
    custom.scaffold(s, "greeter")
    app, hub = server.build(custom.with_custom(s))
    async with connect(app._mcp_server) as c:
        out = await c.call_tool("search_tools", {"query": "hello"})
        assert "greeter.hello" in out.content[0].text
        res = await c.call_tool("call_tool", {"name": "greeter.hello", "arguments": {"who": "piyush"}})
        assert res.content[0].text == "hello piyush"
    await hub.stop()
