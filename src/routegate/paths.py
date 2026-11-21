# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

import re
from dataclasses import dataclass

from .model import PathMatch


@dataclass(frozen=True)
class PathIntersection:
    empty: bool
    certain: bool
    kind: str
    value: str


RANK = {"Exact": 0, "PathPrefix": 1, "RegularExpression": 2}


def compiled(match: PathMatch) -> re.Pattern[str] | None:
    return re.compile(match.value) if match.kind == "RegularExpression" else None


def specificity(match: PathMatch) -> tuple[int, int, str]:
    return (RANK[match.kind], -len(match.value), match.value)


def intersects(first: PathMatch, second: PathMatch) -> PathIntersection:
    a, b = first, second
    if RANK.get(b.kind, 9) < RANK.get(a.kind, 9):
        a, b = b, a

    if a.kind == "Exact" and b.kind == "Exact":
        if a.value == b.value:
            return PathIntersection(False, True, "exact", a.value)
        return PathIntersection(True, True, "none", "")

    if a.kind == "Exact" and b.kind == "PathPrefix":
        if a.value.startswith(b.value):
            return PathIntersection(False, True, "exact", a.value)
        return PathIntersection(True, True, "none", "")

    if a.kind == "PathPrefix" and b.kind == "PathPrefix":
        longer, shorter = (a.value, b.value) if len(a.value) >= len(b.value) else (b.value, a.value)
        if longer.startswith(shorter):
            return PathIntersection(False, True, "prefix", longer)
        return PathIntersection(True, True, "none", "")

    if a.kind == "Exact" and b.kind == "RegularExpression":
        pattern = compiled(b)
        if pattern is not None and pattern.fullmatch(a.value):
            return PathIntersection(False, True, "exact", a.value)
        return PathIntersection(True, True, "none", "")

    if a.kind == "PathPrefix" and b.kind == "RegularExpression":
        pattern = compiled(b)
        if pattern is not None and pattern.fullmatch(a.value):
            return PathIntersection(False, True, "exact", a.value)
        return PathIntersection(False, False, "regex", b.value)

    if a.kind == "RegularExpression" and b.kind == "RegularExpression":
        return PathIntersection(False, a.value == b.value, "regex", a.value)

    return PathIntersection(False, False, "regex", b.value)


def covers(broader: PathMatch, narrower: PathMatch) -> tuple[bool, bool]:
    a, b = broader, narrower
    if a == b:
        return True, True
    if a.kind == "Exact":
        return False, True
    if a.kind == "PathPrefix":
        if b.kind == "Exact":
            return b.value.startswith(a.value), True
        if b.kind == "PathPrefix":
            return b.value.startswith(a.value), True
        return False, True
    pattern = compiled(a)
    if b.kind == "Exact" and pattern is not None:
        return bool(pattern.fullmatch(b.value)), True
    return False, True
