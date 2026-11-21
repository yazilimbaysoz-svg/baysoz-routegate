# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"
PROJECT = "baysoz-routegate"
VERSION = "1.0.0"

Severity = Literal["ERROR", "WARNING", "INFO"]
Certainty = Literal["definite", "possible"]


@dataclass(frozen=True)
class Namespace:
    name: str
    labels: dict[str, str]


@dataclass(frozen=True)
class SelectorExpression:
    key: str
    operator: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class KindConstraint:
    group: str
    kind: str


@dataclass(frozen=True)
class Listener:
    name: str
    protocol: str
    port: int
    hostname: str | None
    allowed_from: str
    selector_labels: dict[str, str]
    selector_expressions: tuple[SelectorExpression, ...]
    allowed_kinds: tuple[KindConstraint, ...]
    gateway: str
    namespace: str
    source: str

    @property
    def qualified(self) -> str:
        return f"{self.namespace}/{self.gateway}:{self.name}"


@dataclass(frozen=True)
class Gateway:
    name: str
    namespace: str
    listeners: tuple[Listener, ...]
    source: str


@dataclass(frozen=True)
class ParentRef:
    name: str
    namespace: str | None
    section_name: str | None
    port: int | None


@dataclass(frozen=True)
class MatchValue:
    kind: str
    value: str | None


@dataclass(frozen=True)
class HeaderMatch:
    name: str
    values: tuple[MatchValue, ...]


@dataclass(frozen=True)
class PathMatch:
    kind: str
    value: str


@dataclass(frozen=True)
class RouteMatch:
    path: PathMatch
    headers: tuple[HeaderMatch, ...]
    query: tuple[HeaderMatch, ...]
    method: str | None


@dataclass(frozen=True)
class BackendRef:
    name: str
    namespace: str | None
    port: int | None


@dataclass(frozen=True)
class Rule:
    index: int
    matches: tuple[RouteMatch, ...]
    backends: tuple[BackendRef, ...]


@dataclass(frozen=True)
class HttpRoute:
    name: str
    namespace: str
    parent_refs: tuple[ParentRef, ...]
    hostnames: tuple[str, ...]
    rules: tuple[Rule, ...]
    creation_stamp: str
    order: int
    source: str


@dataclass(frozen=True)
class AttachedRule:
    route: HttpRoute
    rule: Rule
    listener: Listener
    hostnames: tuple[str, ...]

    @property
    def ident(self) -> str:
        return f"{self.route.namespace}/{self.route.name}:rule[{self.rule.index}]"

    @property
    def order_key(self) -> tuple[str, int, int]:
        return (self.route.creation_stamp, self.route.order, self.rule.index)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    certainty: Certainty
    title: str
    listener: str
    winner: str
    loser: str
    reason: str
    remedy: str
    winner_source: str
    loser_source: str
    detail: str = ""

    @property
    def fingerprint(self) -> str:
        return "|".join(
            (
                self.code,
                self.listener,
                self.winner,
                self.loser,
                self.winner_source,
                self.loser_source,
            )
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "certainty": self.certainty,
            "title": self.title,
            "listener": self.listener,
            "winner": self.winner,
            "loser": self.loser,
            "reason": self.reason,
            "remedy": self.remedy,
            "winner_source": self.winner_source,
            "loser_source": self.loser_source,
            "detail": self.detail,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class AnalysisResult:
    findings: tuple[Finding, ...]
    stats: dict[str, int]
