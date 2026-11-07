import re

import pytest

from mcpgate import cli, server


def test_skill_has_valid_frontmatter_and_mentions_every_meta_tool(capsys):
    assert cli.main(["skill", "show"]) == 0
    text = capsys.readouterr().out
    m = re.match(r"---\nname: (.+)\ndescription: (.+)\n---\n", text)
    assert m and m.group(1) == "mcp-gateway" and len(m.group(2)) < 1024
    for tool in ["search_tools", "describe_tool", "call_tool", "read_result", "list_backends"]:
        assert tool in text


def test_skill_matches_the_server_instructions_vocabulary():
    # the advice must use the argument names the server really has
    text = cli._skill_text()
    for word in ["confirm", "backend", "offset", "result_id"]:
        assert word in text
    assert "search_tools" in server.INSTRUCTIONS and "confirm" in server.INSTRUCTIONS


def test_install_writes_the_skill_and_refuses_to_overwrite(tmp_path, capsys):
    assert cli.main(["skill", "install", "--dir", str(tmp_path)]) == 0
    f = tmp_path / "mcp-gateway" / "SKILL.md"
    assert f.read_text() == cli._skill_text()
    f.write_text("mine")
    assert cli.main(["skill", "install", "--dir", str(tmp_path)]) == 2
    assert f.read_text() == "mine"
    assert cli.main(["skill", "install", "--dir", str(tmp_path), "--force"]) == 0
    assert f.read_text() == cli._skill_text()
