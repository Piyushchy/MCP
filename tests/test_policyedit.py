import itertools
import random
from types import SimpleNamespace as T

import pytest

from mcpgate.admin.policyedit import STATES, Conflict, Rules, apply, options, state_of
from mcpgate.policy import Policy

TOOLS = {n: T(name=n, destructive=d) for n, d in [("echo", False), ("add", False), ("delete_note", False), ("create_note", False),
                                                  ("list_notes", False), ("wipe", True)]}


def test_state_of_matches_the_gateway_policy_for_every_combination():
    patterns = [[], ["*"], ["list_*"], ["echo"], ["delete_*", "wipe"]]
    for allow, deny, confirm in itertools.product(patterns[1:], patterns, patterns):
        r = Rules(allow, deny, confirm)
        pol = Policy(allow, deny, confirm)
        for name, t in TOOLS.items():
            st, _ = state_of(r, name, t.destructive)
            assert (st != "block") == pol.visible(name)
            if pol.visible(name):
                assert (st == "confirm") == pol.needs_confirm(name, t.destructive)


def test_deny_wins_over_allow_in_the_displayed_state():
    r = Rules(allow=["echo"], deny=["echo"])
    assert state_of(r, "echo", False) == ("block", 'blocked by the deny pattern "echo"')
    assert state_of(Rules(allow=["list_*"]), "echo", False) == ("block", "not in the allow list")


def test_destructive_hint_always_needs_approval():
    st, why = state_of(Rules(), "wipe", True)
    assert st == "confirm" and "destructive" in why


def test_existing_globs_survive_untouched():
    r = Rules(["*"], ["delete_*"], ["create_*"])
    new = apply(r, TOOLS, {"echo": "block"})
    assert new.deny == ["delete_*", "echo"] and new.confirm == ["create_*"] and new.allow == ["*"]
    back = apply(new, TOOLS, {"echo": "allow"})
    assert back == r


def test_unchanged_tools_do_not_change():
    r = Rules(["*"], ["delete_*"], ["create_*"])
    assert apply(r, TOOLS, {}) == r
    assert apply(r, TOOLS, {"delete_note": "block"}) == r        # already blocked by the glob: nothing added
    assert apply(r, TOOLS, {"create_note": "confirm"}) == r


def test_conflicts_with_globs_are_reported_not_ignored():
    r = Rules(["*"], ["delete_*"], ["create_*"])
    with pytest.raises(Conflict, match='deny pattern "delete_\\*"'):
        apply(r, TOOLS, {"delete_note": "allow"})
    with pytest.raises(Conflict, match='pattern "create_\\*"'):
        apply(r, TOOLS, {"create_note": "allow"})
    assert apply(r, TOOLS, {"delete_note": "confirm"}, {"deny": ["delete_*"]}).deny == []     # after removing the pattern it works
    assert apply(r, TOOLS, {"create_note": "allow"}, {"confirm": ["create_*"]}).confirm == []


def test_restrictive_allow_list_gets_exact_names():
    r = Rules(["list_*"])
    new = apply(r, TOOLS, {"echo": "confirm"})
    assert new.allow == ["list_*", "echo"] and new.confirm == ["echo"]
    assert apply(new, TOOLS, {"echo": "block"}) == Rules(["list_*"])      # block removes what was added


def test_destructive_tool_rules():
    with pytest.raises(Conflict, match="destructive"):
        apply(Rules(), TOOLS, {"wipe": "allow"})
    assert apply(Rules(), TOOLS, {"wipe": "confirm"}) == Rules()           # already needs approval: no entry needed
    assert apply(Rules(), TOOLS, {"wipe": "block"}).deny == ["wipe"]


def test_removing_every_allow_pattern_falls_back_to_default_not_to_nothing():
    assert apply(Rules(["list_*"]), TOOLS, {}, {"allow": ["list_*"]}).allow == ["*"]


def test_options_report_why_a_state_is_unavailable():
    o = options(Rules(["*"], ["delete_*"], ["create_*"]), TOOLS, "delete_note")
    assert o["allow"] and o["confirm"] and o["block"] is None
    o = options(Rules(), TOOLS, "wipe")
    assert "destructive" in o["allow"] and o["confirm"] is None and o["block"] is None
    assert options(Rules(), TOOLS, "echo") == {"allow": None, "confirm": None, "block": None}


def test_every_reachable_state_is_really_reached_and_nothing_else_moves():
    rnd = random.Random(7)
    names = list(TOOLS)
    pats = names + ["delete_*", "create_*", "list_*", "*", "e*", "w*"]
    for _ in range(400):
        r = Rules(allow=rnd.sample(pats, rnd.randint(1, 3)), deny=rnd.sample(pats, rnd.randint(0, 2)), confirm=rnd.sample(pats, rnd.randint(0, 2)))
        before = {n: state_of(r, n, TOOLS[n].destructive)[0] for n in names}
        tool, want = rnd.choice(names), rnd.choice(STATES)
        try:
            new = apply(r, TOOLS, {tool: want})
        except Conflict:
            continue
        after = {n: state_of(new, n, TOOLS[n].destructive)[0] for n in names}
        assert after[tool] == want, (r, tool, want, new)
        assert {n: s for n, s in after.items() if n != tool} == {n: s for n, s in before.items() if n != tool}, (r, tool, want, new)
        for glob in [p for p in r.allow + r.deny + r.confirm if "*" in p]:       # hand-written globs are never dropped
            assert glob in new.allow + new.deny + new.confirm
        assert len(new.deny) <= len(r.deny) + 1 and len(new.confirm) <= len(r.confirm) + 1 and len(new.allow) <= len(r.allow) + 1
