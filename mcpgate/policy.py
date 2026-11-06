"""Which tools of a backend the model may see, and which need a human yes first."""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase


def matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(name, p) for p in patterns)


@dataclass
class Policy:
    allow: list[str] = field(default_factory=lambda: ["*"])
    deny: list[str] = field(default_factory=list)
    confirm: list[str] = field(default_factory=list)

    def visible(self, tool: str) -> bool:
        """Deny always wins over allow."""
        return matches(tool, self.allow) and not matches(tool, self.deny)

    def needs_confirm(self, tool: str, destructive_hint: bool = False) -> bool:
        return matches(tool, self.confirm) or destructive_hint
