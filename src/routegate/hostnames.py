# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

import re

_HOSTNAME_RE = re.compile(
    r"^(?:\*|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)


def normalize(value: str) -> str:
    return value.strip().lower().rstrip(".")


def is_valid(value: str) -> bool:
    return bool(value) and bool(_HOSTNAME_RE.fullmatch(value))


def _labels(value: str) -> list[str]:
    return value.split(".")


def matches_exact(pattern: str, hostname: str) -> bool:
    if pattern == "*":
        return True
    target = _labels(hostname)
    candidate = _labels(pattern)
    if candidate[0] == "*":
        return len(candidate) == len(target) and candidate[1:] == target[1:]
    return candidate == target


def intersects(first: str, second: str) -> bool:
    if first == "*" or second == "*":
        return True
    if first == second:
        return True
    if len(_labels(first)) != len(_labels(second)):
        return False
    if first.startswith("*."):
        return matches_exact(first, second)
    if second.startswith("*."):
        return matches_exact(second, first)
    return False


def covers(broader: str, narrower: str) -> bool:
    if broader == "*":
        return True
    if broader == narrower:
        return True
    if not broader.startswith("*."):
        return False
    return matches_exact(broader, narrower)


def specificity(value: str) -> tuple[int, int]:
    if value == "*":
        return (2, 0)
    if value.startswith("*."):
        return (1, -len(_labels(value)))
    return (0, -len(_labels(value)))
