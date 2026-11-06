import pytest

from mcpgate.policy import Policy
from mcpgate.trim import ResultStore, cap, short


def test_allow_and_deny_with_deny_winning():
    p = Policy(allow=["read_*", "list_*", "delete_all"], deny=["delete_*"])
    assert p.visible("read_file") and p.visible("list_things")
    assert not p.visible("write_file")
    assert not p.visible("delete_all")  # allowed and denied -> denied


def test_default_policy_allows_everything():
    p = Policy()
    assert p.visible("anything") and not p.needs_confirm("anything")


def test_confirm_patterns_and_destructive_hint():
    p = Policy(confirm=["create_*"])
    assert p.needs_confirm("create_issue")
    assert not p.needs_confirm("get_issue")
    assert p.needs_confirm("get_issue", destructive_hint=True)


def test_short_description():
    assert short(None) == "" and short("") == ""
    assert short("Reads a file. It also does a lot of other things you rarely need.") == "Reads a file."
    long = "x" * 500
    out = short(long, 50)
    assert len(out) == 50 and out.endswith("…")
    assert short("line one\nline two", 160) == "line one line two"


def test_cap_passes_small_text_through():
    store = ResultStore()
    assert cap("hello", 100, store) == "hello"


def test_cap_cuts_and_pages():
    store = ResultStore()
    text = "".join(str(i % 10) for i in range(1000))
    out = cap(text, 300, store)
    assert out.startswith(text[:300]) and "700" not in out.split("\n\n")[0]
    rid = out.split('result_id="')[1].split('"')[0]
    chunk, total = store.read(rid, 300, 400)
    assert total == 1000 and chunk == text[300:700]
    chunk, _ = store.read(rid, 700, 10_000)
    assert chunk == text[700:]


def test_store_forgets_oldest_and_rejects_unknown():
    store = ResultStore(keep=2)
    ids = [store.put(str(i)) for i in range(3)]
    with pytest.raises(KeyError):
        store.read(ids[0])
    assert store.read(ids[2])[0] == "2"
