# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

import re

from . import paths
from .model import MatchValue, RouteMatch


def _compiled(value: MatchValue) -> re.Pattern[str] | None:
    return re.compile(value.value or "") if value.kind == "RegularExpression" else None


def value_intersects(first: MatchValue, second: MatchValue) -> tuple[bool, bool]:
    if first.kind == "Present" or second.kind == "Present":
        return False, True
    if first.kind == "Exact" and second.kind == "Exact":
        return first.value != second.value, True
    if first.kind == "Exact" and second.kind == "Prefix":
        return not (first.value or "").startswith(second.value or ""), True
    if first.kind == "Prefix" and second.kind == "Exact":
        return not (second.value or "").startswith(first.value or ""), True
    if first.kind == "Prefix" and second.kind == "Prefix":
        a, b = first.value or "", second.value or ""
        return not (a.startswith(b) or b.startswith(a)), True
    if first.kind == "RegularExpression" and second.kind == "RegularExpression":
        return False, False
    regex = first if first.kind == "RegularExpression" else second
    literal = second if regex is first else first
    pattern = _compiled(regex)
    if pattern is None:
        return False, False
    text = literal.value or ""
    if literal.kind == "Exact":
        return not bool(pattern.fullmatch(text)), True
    if literal.kind == "Prefix" and pattern.fullmatch(text):
        return False, True
    return False, False


def value_covers(broader: MatchValue, narrower: MatchValue) -> tuple[bool, bool]:
    if broader.kind == "Present":
        return True, True
    if narrower.kind == "Present":
        return False, True
    if broader.kind == "Exact":
        return broader.value == narrower.value, True
    if broader.kind == "Prefix":
        if narrower.kind == "Exact":
            return (narrower.value or "").startswith(broader.value or ""), True
        if narrower.kind == "Prefix":
            return (narrower.value or "").startswith(broader.value or ""), True
        return False, True
    if narrower.kind == "Exact":
        pattern = _compiled(broader)
        return bool(pattern is not None and pattern.fullmatch(narrower.value or "")), True
    if broader == narrower:
        return True, True
    return False, True


def _groups(match: RouteMatch, field: str) -> dict[str, tuple[MatchValue, ...]]:
    return {item.name: item.values for item in getattr(match, field)}


def constraint_intersects(
    first: dict[str, tuple[MatchValue, ...]], second: dict[str, tuple[MatchValue, ...]]
) -> tuple[bool, bool]:
    certain = True
    for name in set(first) | set(second):
        left = first.get(name, ())
        right = second.get(name, ())
        if not left or not right:
            continue
        results = [value_intersects(a, b) for a in left for b in right]
        if all(empty for empty, _ in results):
            return True, True
        if not any(certain_result for _, certain_result in results):
            certain = False
    return False, certain


def constraint_covers(
    first: dict[str, tuple[MatchValue, ...]], second: dict[str, tuple[MatchValue, ...]]
) -> tuple[bool, bool]:
    if not set(first).issubset(set(second)):
        return False, True
    certain = True
    for name, right_values in second.items():
        left_values = first.get(name, ())
        if not right_values:
            continue
        if not left_values:
            continue
        for right in right_values:
            options = [value_covers(left, right) for left in left_values]
            if any(covered and sure for covered, sure in options):
                continue
            if any(covered for covered, _ in options):
                certain = False
                continue
            return False, True
    return True, certain


def method_intersects(first: str | None, second: str | None) -> bool:
    return first is None or second is None or first == second


def method_covers(broader: str | None, narrower: str | None) -> bool:
    return broader is None or broader == narrower


def route_intersects(first: RouteMatch, second: RouteMatch) -> tuple[bool, bool]:
    path = paths.intersects(first.path, second.path)
    if path.empty:
        return False, True
    if not method_intersects(first.method, second.method):
        return False, True
    headers_empty, headers_certain = constraint_intersects(
        _groups(first, "headers"), _groups(second, "headers")
    )
    query_empty, query_certain = constraint_intersects(
        _groups(first, "query"), _groups(second, "query")
    )
    if headers_empty or query_empty:
        return False, True
    return True, path.certain and headers_certain and query_certain


def route_covers(broader: RouteMatch, narrower: RouteMatch) -> tuple[bool, bool]:
    path_covered, path_certain = paths.covers(broader.path, narrower.path)
    if not path_covered:
        return False, path_certain
    if not method_covers(broader.method, narrower.method):
        return False, True
    headers_covered, headers_certain = constraint_covers(
        _groups(broader, "headers"), _groups(narrower, "headers")
    )
    if not headers_covered:
        return False, headers_certain
    query_covered, query_certain = constraint_covers(
        _groups(broader, "query"), _groups(narrower, "query")
    )
    if not query_covered:
        return False, query_certain
    return True, path_certain and headers_certain and query_certain


def match_specificity(match: RouteMatch) -> tuple:
    return (
        paths.specificity(match.path),
        -len(match.headers),
        -len(match.query),
        0 if match.method else 1,
    )
