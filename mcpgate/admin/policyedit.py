"""Turning "this tool should be Allowed / Needs approval / Blocked" into allow/deny/confirm patterns.

Hand-written glob patterns are never rewritten. Only exact tool names for the tools the admin actually changed are
added or removed, and a request that a glob makes impossible is reported instead of silently ignored."""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from ..policy import Policy, matches

STATES = ("allow", "confirm", "block")


class Conflict(Exception):
    pass


@dataclass
class Rules:
    allow: list[str] = field(default_factory=lambda: ["*"])
    deny: list[str] = field(default_factory=list)
    confirm: list[str] = field(default_factory=list)

    def policy(self) -> Policy:
        return Policy(list(self.allow), list(self.deny), list(self.confirm))

    def key(self) -> tuple:
        return (tuple(self.allow), tuple(self.deny), tuple(self.confirm))


def first(name: str, patterns: list[str]) -> str:
    return next(p for p in patterns if fnmatchcase(name, p))


def state_of(rules: Rules, name: str, destructive: bool) -> tuple[str, str]:
    """(state, why). Deny wins over allow, exactly as in the gateway; a destructive hint always needs approval."""
    if matches(name, rules.deny):
        return "block", f'blocked by the deny pattern "{first(name, rules.deny)}"'
    if not matches(name, rules.allow):
        return "block", "not in the allow list"
    if matches(name, rules.confirm):
        return "confirm", f'needs approval by the pattern "{first(name, rules.confirm)}"'
    if destructive:
        return "confirm", "the server marks it destructive, so it always needs approval"
    return "allow", ""


def _uniq(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def apply(rules: Rules, tools: dict, changes: dict[str, str], remove: dict[str, list[str]] | None = None) -> Rules:
    """New rules after ``changes`` ({tool: state}) and removal of whole patterns. Raises Conflict when a state is impossible."""
    remove = remove or {}
    allow = [p for p in rules.allow if p not in remove.get("allow", [])]
    deny = [p for p in rules.deny if p not in remove.get("deny", [])]
    confirm = [p for p in rules.confirm if p not in remove.get("confirm", [])]
    if not allow:
        allow = ["*"]   # no allow patterns would hide every tool; that is what "block" is for
    for name, want in changes.items():
        deny = [p for p in deny if p != name]
        confirm = [p for p in confirm if p != name]
        allow = [p for p in allow if p != name]
        if want == "block":
            if matches(name, allow) and not matches(name, deny):   # not already blocked some other way
                deny.append(name)
            continue
        if matches(name, deny):
            raise Conflict(f'"{name}" is blocked by the deny pattern "{first(name, deny)}". Remove that pattern first.')
        if not matches(name, allow):
            allow.append(name)
        if want == "confirm":
            if not matches(name, confirm) and not tools[name].destructive:
                confirm.append(name)
        else:
            if matches(name, confirm):
                raise Conflict(f'"{name}" needs approval by the pattern "{first(name, confirm)}". Remove that pattern first.')
            if tools[name].destructive:
                raise Conflict(f'"{name}" is marked destructive by its server, so it always needs approval.')
    return Rules(_uniq(allow), _uniq(deny), _uniq(confirm))


def options(rules: Rules, tools: dict, name: str) -> dict[str, str | None]:
    """For each state: None if it can be chosen, otherwise why not."""
    out: dict[str, str | None] = {}
    for st in STATES:
        try:
            apply(rules, tools, {name: st})
            out[st] = None
        except Conflict as e:
            out[st] = str(e)
    return out
