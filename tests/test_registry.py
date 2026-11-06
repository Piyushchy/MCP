import pytest

from mcpgate.backends import ToolInfo
from mcpgate.registry import rank, split_name, words


def T(backend, name, desc=""):
    return ToolInfo(backend=backend, name=name, description=desc, schema={})


TOOLS = [
    T("github", "create_issue", "Create a new issue in a repository."),
    T("github", "list_issues", "List issues in a repository."),
    T("github", "get_file_contents", "Read a file from a repository."),
    T("files", "list_files", "List files in a folder of the personal drive."),
    T("files", "upload_file", "Upload a file to the personal drive."),
    T("mail", "send_message", "Send an email message."),
    T("mail", "search_threads", "Search email threads."),
]


def names(res):
    return [t.full for t in res]


def test_words_splits_snake_and_camel():
    assert words("create_issue") == ["create", "issue"]
    assert words("getFileContents") == ["get", "file", "contents"]


def test_split_name():
    assert split_name("github.create_issue") == ("github", "create_issue")
    assert split_name("a.b.c") == ("a", "b.c")
    for bad in ["nodot", ".x", "x."]:
        with pytest.raises(ValueError):
            split_name(bad)


def test_name_match_beats_description_match():
    assert names(rank(TOOLS, "upload"))[0] == "files.upload_file"
    assert names(rank(TOOLS, "email"))[0] in {"mail.send_message", "mail.search_threads"}


def test_multi_word_queries_prefer_tools_matching_all_words():
    assert names(rank(TOOLS, "create issue"))[0] == "github.create_issue"
    assert names(rank(TOOLS, "list files drive"))[0] == "files.list_files"


def test_backend_name_counts():
    res = names(rank(TOOLS, "mail"))
    assert set(res[:2]) == {"mail.send_message", "mail.search_threads"}


def test_exact_full_name_is_first():
    assert names(rank(TOOLS, "files.list_files"))[0] == "files.list_files"


def test_no_match_returns_nothing_and_empty_query_lists_sorted():
    assert rank(TOOLS, "zzzzqqq") == []
    assert names(rank(TOOLS, "", limit=3)) == ["files.list_files", "files.upload_file", "github.create_issue"]


def test_limit():
    assert len(rank(TOOLS, "file", limit=2)) == 2
