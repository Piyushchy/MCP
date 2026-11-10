import json
import os
import random
import subprocess
import sys
import threading
import time

import pytest

from mcpgate import auditlog
from mcpgate.audit import Audit, rotated


def write(path, rows):
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def mode(p):
    return p.stat().st_mode & 0o777


# -- reading backwards ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("chunk", [1, 7, 64, 100000])
def test_backwards_returns_every_line_with_true_offsets(tmp_path, monkeypatch, chunk):
    monkeypatch.setattr(auditlog, "CHUNK", chunk)
    rng = random.Random(chunk)
    lines = ["".join(rng.choice("abc é日本\t{}\"") for _ in range(rng.randint(1, 40))) for _ in range(60)]
    p = tmp_path / "f"
    p.write_text("\n".join(lines) + "\n")
    raw = p.read_bytes()
    with open(p, "rb") as f:
        got = list(auditlog.backwards(f, len(raw)))
    assert [g[1].decode() for g in got] == lines[::-1]
    for start, line in got:
        assert raw[start:start + len(line)] == line and (start == 0 or raw[start - 1:start] == b"\n")


def test_backwards_without_trailing_newline_and_from_the_middle(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"one\ntwo\nthree")
    with open(p, "rb") as f:
        assert [x[1] for x in auditlog.backwards(f, 13)] == [b"three", b"two", b"one"]
        assert [x[1] for x in auditlog.backwards(f, 8)] == [b"two", b"one"]      # a cursor: only what is before it
        assert list(auditlog.backwards(f, 0)) == []


# -- filters and paging -----------------------------------------------------------------------------------------
def sample(n=1000):
    rows = []
    for i in range(n):
        if i % 50 == 0:
            rows.append({"ts": 1000 + i, "event": "admin_login_failed"})
        elif i % 7 == 0:
            rows.append({"ts": 1000 + i, "event": "approval_denied", "tool": "demo.wipe", "id": f"r{i}"})
        else:
            b = ["demo", "github", "docs"][i % 3]
            rows.append({"ts": 1000 + i, "tool": f"{b}.echo" if i % 2 else f"{b}.add", "args": {"text": f"hello {i}"}, "status": "ok" if i % 5 else "tool_error", "ms": i})
    return rows


def test_newest_first_and_cursor_pages_have_no_gaps_or_repeats(tmp_path):
    p = tmp_path / "a.jsonl"
    rows = sample(1000)
    write(p, rows)
    seen, cur = [], None
    while True:
        r = auditlog.page(p, limit=77, cursor=cur)
        seen += [e["ts"] for e in r["entries"]]
        cur = r["next"]
        if not cur:
            break
    assert seen == [e["ts"] for e in rows][::-1]


def test_filters(tmp_path):
    p = tmp_path / "a.jsonl"
    write(p, sample(1000))
    def ts(**kw):
        out, cur = [], None
        while True:
            r = auditlog.page(p, limit=50, cursor=cur, **kw)
            out += r["entries"]
            cur = r["next"]
            if not cur:
                return out
    assert {auditlog.backend_of(e) for e in ts(backend="github")} == {"github"}
    assert all(e["status"] == "tool_error" for e in ts(status="tool_error"))
    assert all("event" not in e for e in ts(kind="call")) and all(e["event"].startswith("admin_") for e in ts(kind="admin"))
    assert {e["event"] for e in ts(kind="approval")} == {"approval_denied"}
    assert all("echo" in e["tool"] for e in ts(tool="ECHO"))
    assert [e["ts"] for e in ts(q="hello 997")] == [1997]
    assert all(1500 <= e["ts"] <= 1600 for e in ts(since=1500, until=1600)) and len(ts(since=1500, until=1600)) == 101
    assert ts(backend="nobody") == []


def test_search_matches_inside_arguments_and_unicode(tmp_path):
    p = tmp_path / "a.jsonl"
    write(p, [{"ts": 1, "tool": "d.x", "args": {"t": "Zażółć"}, "status": "ok"}, {"ts": 2, "tool": "d.x", "args": {"t": "plain"}, "status": "ok"}])
    assert [e["ts"] for e in auditlog.page(p, q="żółć".upper())["entries"]] in ([1], [])   # raw lines hold \u escapes
    assert [e["ts"] for e in auditlog.page(p, q="plain")["entries"]] == [2]


def test_bad_and_oversized_lines_are_skipped_not_fatal(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_bytes(b'{"ts":1,"tool":"d.a","status":"ok"}\nnot json at all\n[1,2]\n' + b'{"ts":2,"pad":"' + b"x" * (auditlog.MAX_LINE + 5) + b'"}\n{"ts":3,"tool":"d.b","status":"ok"}\n')
    r = auditlog.page(p)
    assert [e["ts"] for e in r["entries"]] == [3, 1] and r["bad"] == 3


def test_bad_cursor_and_missing_file(tmp_path):
    with pytest.raises(ValueError):
        auditlog.page(tmp_path / "a", cursor="../../etc/passwd")
    assert auditlog.page(tmp_path / "nothing.jsonl")["entries"] == []


# -- big logs ---------------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def big(tmp_path_factory):
    p = tmp_path_factory.mktemp("big") / "audit.jsonl"
    with open(p, "w") as f:
        for i in range(150_000):
            e = {"ts": 1_700_000_000 + i, "tool": f"{['demo', 'github'][i % 2]}.echo", "args": {"text": f"line {i}"}, "status": "ok", "ms": 3}
            if i == 3:
                e["status"] = "refused"
            f.write(json.dumps(e) + "\n")
    return p


def test_latest_page_of_a_huge_log_is_instant(big):
    t = time.perf_counter()
    r = auditlog.page(big, limit=100)
    took = time.perf_counter() - t
    assert len(r["entries"]) == 100 and r["entries"][0]["args"]["text"] == "line 149999" and r["scanned"] == 100
    assert took < 0.1, took


def test_filters_and_paging_stay_fast_and_bounded_on_100k_plus_lines(big):
    t = time.perf_counter()
    r = auditlog.page(big, limit=100, backend="github")
    assert len(r["entries"]) == 100 and time.perf_counter() - t < 0.2
    t = time.perf_counter()
    r = auditlog.page(big, limit=100, status="refused")          # rare: one line, three from the start
    took = time.perf_counter() - t
    assert r["scanned"] == auditlog.MAX_SCAN and r["entries"] == [] and r["next"], "a request is bounded; it hands back a cursor"
    assert took < 5, took
    r = auditlog.page(big, limit=100, status="refused", cursor=r["next"])
    assert len(r["entries"]) == 1 and r["entries"][0]["ts"] == 1_700_000_003 and r["next"] is None
    t = time.perf_counter()
    assert auditlog.page(big, limit=100, since=1_700_000_000 + 149_950)["next"] is None      # time filter stops early
    assert time.perf_counter() - t < 0.1


# -- rotation ---------------------------------------------------------------------------------------------------
def test_rotates_by_size_keeps_n_files_private(tmp_path):
    p = tmp_path / "audit.jsonl"
    a = Audit(str(p), max_bytes=2000, keep=3)
    for i in range(200):
        a.log(tool="d.echo", status="ok", n=i, pad="x" * 50)
    files = auditlog.log_files(p)
    assert [f.name for f in files] == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.3"]
    assert not rotated(p, 4).exists()
    assert all(mode(f) == 0o600 for f in files)
    assert all(f.stat().st_size <= 2200 for f in files)
    ns = [e["n"] for e in auditlog.page(p, limit=200)["entries"]]
    assert ns == sorted(ns, reverse=True) and ns[0] == 199 and len(set(ns)) == len(ns)         # newest first across files


def test_no_line_is_lost_with_concurrent_writers_in_one_process(tmp_path):
    p = tmp_path / "audit.jsonl"
    def worker(w):
        a = Audit(str(p), max_bytes=20_000, keep=50)          # separate instances, like separate parts of the program
        for i in range(400):
            a.log(w=w, i=i, pad="y" * 40)
    ts = [threading.Thread(target=worker, args=(w,)) for w in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    seen = set()
    for f in auditlog.log_files(p):
        for line in f.read_text().splitlines():
            e = json.loads(line)                              # every line whole
            assert (e["w"], e["i"]) not in seen
            seen.add((e["w"], e["i"]))
    assert len(seen) == 8 * 400 and len(auditlog.log_files(p)) > 3
    assert all(mode(f) == 0o600 for f in auditlog.log_files(p))


def test_no_line_is_lost_with_concurrent_processes(tmp_path):
    p = tmp_path / "audit.jsonl"
    code = ("import sys\nfrom mcpgate.audit import Audit\na = Audit(sys.argv[1], max_bytes=20000, keep=50)\n"
            "for i in range(300):\n    a.log(w=int(sys.argv[2]), i=i, pad='z' * 40)\n")
    procs = [subprocess.Popen([sys.executable, "-c", code, str(p), str(w)], env={**os.environ, "PYTHONPATH": os.getcwd()}) for w in range(4)]
    assert [x.wait(timeout=60) for x in procs] == [0] * 4
    seen = {(json.loads(line)["w"], json.loads(line)["i"]) for f in auditlog.log_files(p) for line in f.read_text().splitlines()}
    assert len(seen) == 4 * 300


def test_beyond_keep_the_oldest_file_is_dropped_on_purpose(tmp_path):
    p = tmp_path / "audit.jsonl"
    a = Audit(str(p), max_bytes=500, keep=1)
    for i in range(100):
        a.log(n=i, pad="x" * 40)
    assert len(auditlog.log_files(p)) == 2 and auditlog.page(p, limit=200)["entries"][0]["n"] == 99


def test_cursor_survives_a_rotation_without_repeating_or_guessing(tmp_path):
    p = tmp_path / "audit.jsonl"
    a = Audit(str(p), max_bytes=3000, keep=2)
    for i in range(60):
        a.log(n=i, pad="x" * 30)
    first = auditlog.page(p, limit=10)
    assert first["next"]
    for i in range(60, 400):
        a.log(n=i, pad="x" * 30)                               # the file the cursor pointed at is long gone
    later = auditlog.page(p, limit=10, cursor=first["next"])
    assert later["stale"] is True and later["entries"] == []


def test_writer_never_raises_and_stream_is_oldest_first(tmp_path):
    p = tmp_path / "audit.jsonl"
    a = Audit(str(p), max_bytes=800, keep=5)
    for i in range(40):
        a.log(n=i, pad="x" * 30)
    got = [json.loads(line)["n"] for line in b"".join(auditlog.stream(p)).decode().splitlines()]
    assert got == sorted(got) and got[-1] == 39
    Audit("/proc/nope/audit.jsonl").log(a=1)                  # unwritable: silently ignored
