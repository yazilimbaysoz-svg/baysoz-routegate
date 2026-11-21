# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from . import hostnames, matches, paths
from .loader import GROUP, ManifestSet
from .model import (
    VERSION,
    AnalysisResult,
    AttachedRule,
    Certainty,
    Finding,
    HttpRoute,
    Listener,
    Severity,
)

_FACTORS = (
    "hostname specificity",
    "path specificity",
    "header constraint count",
    "HTTP method constraint",
    "query constraint count",
    "creation timestamp",
    "input order",
    "stable identity tie-break",
    "listener attachment",
)
_SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}


@dataclass(frozen=True)
class _Candidate:
    finding: Finding
    rank: tuple


def _selector_matches(
    listener: Listener, route: HttpRoute, namespace_labels: dict[str, str]
) -> bool:
    if listener.allowed_from == "All":
        return True
    if listener.allowed_from == "Same":
        return route.namespace == listener.namespace
    for key, expected in listener.selector_labels.items():
        if namespace_labels.get(key) != expected:
            return False
    for expression in listener.selector_expressions:
        actual = namespace_labels.get(expression.key)
        if expression.operator == "In" and actual not in expression.values:
            return False
        if expression.operator == "NotIn" and actual in expression.values:
            return False
        if expression.operator == "Exists" and expression.key not in namespace_labels:
            return False
        if expression.operator == "DoesNotExist" and expression.key in namespace_labels:
            return False
    return True


def _parent_matches(route: HttpRoute, listener: Listener) -> bool:
    return any(
        ref.name == listener.gateway
        and (ref.namespace is None or ref.namespace == listener.namespace)
        and (ref.section_name is None or ref.section_name == listener.name)
        and (ref.port is None or ref.port == listener.port)
        for ref in route.parent_refs
    )


def _effective_hostnames(route: HttpRoute, listener: Listener) -> tuple[str, ...]:
    if route.hostnames:
        return route.hostnames
    return (listener.hostname or "*",)


def _attach(manifests: ManifestSet) -> tuple[list[AttachedRule], list[Finding]]:
    attached: list[AttachedRule] = []
    findings: list[Finding] = []
    namespace_labels = {item.name: item.labels for item in manifests.namespaces}
    for route in manifests.routes:
        reasons: list[str] = []
        for gateway in manifests.gateways:
            for listener in gateway.listeners:
                if listener.protocol not in {"HTTP", "HTTPS"}:
                    reasons.append(f"{listener.qualified}: protocol {listener.protocol}")
                    continue
                if not _parent_matches(route, listener):
                    reasons.append(f"{listener.qualified}: no matching parentRef")
                    continue
                if not _selector_matches(
                    listener, route, namespace_labels.get(route.namespace, {})
                ):
                    reasons.append(f"{listener.qualified}: namespace not allowed by allowedRoutes")
                    continue
                if listener.allowed_kinds and not any(
                    kind.group == GROUP and kind.kind == "HTTPRoute"
                    for kind in listener.allowed_kinds
                ):
                    reasons.append(f"{listener.qualified}: HTTPRoute kind not allowed")
                    continue
                effective = _effective_hostnames(route, listener)
                if listener.hostname is not None and not any(
                    hostnames.intersects(name, listener.hostname) for name in effective
                ):
                    reasons.append(f"{listener.qualified}: hostname does not intersect listener")
                    continue
                for rule in route.rules:
                    attached.append(AttachedRule(route, rule, listener, effective))
        if not any(item.route is route for item in attached) and reasons:
            findings.append(
                Finding(
                    "RG1004",
                    "WARNING",
                    "definite",
                    "ROUTE_NOT_ATTACHED",
                    ", ".join(sorted({text.split(":", maxsplit=1)[0] for text in reasons}))
                    or "none",
                    "-",
                    f"{route.namespace}/{route.name}",
                    "; ".join(sorted(set(reasons))),
                    "Fix parentRefs, hostname, namespace selector or protocol compatibility.",
                    route.source,
                    route.source,
                )
            )
    return attached, findings


def _specificity(attached: AttachedRule, hostname: str, match) -> tuple:
    return (
        hostnames.specificity(hostname),
        paths.specificity(match.path),
        -len(match.headers),
        0 if match.method else 1,
        -len(match.query),
    )


def _decision_key(attached: AttachedRule, hostname: str, match) -> tuple:
    return (
        *_specificity(attached, hostname, match),
        attached.route.creation_stamp,
        attached.route.order,
        attached.rule.index,
        attached.ident,
    )


def _tie_key(attached: AttachedRule, hostname: str, match) -> tuple:
    return (*_specificity(attached, hostname, match), attached.route.creation_stamp)


def _reason(left: tuple, right: tuple) -> str:
    for index, (a, b) in enumerate(zip(left, right, strict=True)):
        if a != b:
            return f"{_FACTORS[index]} favours the winner ({a} vs {b})"
    return "stable tie-break favours the winner"


def _hostnames_cover(broader: AttachedRule, narrower: AttachedRule) -> bool:
    return all(
        any(hostnames.covers(candidate, target) for candidate in broader.hostnames)
        for target in narrower.hostnames
    )


def _backends(attached: AttachedRule) -> tuple:
    return tuple(
        sorted((item.name, item.namespace or "", item.port or 0) for item in attached.rule.backends)
    )


def _certainty(sure: bool) -> Certainty:
    return "definite" if sure else "possible"


def _severity(sure: bool, benign: bool) -> Severity:
    if benign:
        return "INFO"
    return "ERROR" if sure else "WARNING"


def _conflicts(attached: list[AttachedRule]) -> list[Finding]:
    candidates: dict[str, _Candidate] = {}
    by_listener: dict[str, list[AttachedRule]] = {}
    for item in attached:
        by_listener.setdefault(item.listener.qualified, []).append(item)

    for listener_name, items in by_listener.items():
        for first_index, first in enumerate(items):
            for second in items[first_index + 1 :]:
                if first.route is second.route and first.rule.index == second.rule.index:
                    continue
                best: _Candidate | None = None
                for host_first in first.hostnames:
                    for host_second in second.hostnames:
                        if not hostnames.intersects(host_first, host_second):
                            continue
                        for match_first in first.rule.matches:
                            for match_second in second.rule.matches:
                                intersects, sure = matches.route_intersects(
                                    match_first, match_second
                                )
                                if not intersects:
                                    continue
                                candidate = _evaluate_pair(
                                    listener_name,
                                    first,
                                    second,
                                    host_first,
                                    host_second,
                                    match_first,
                                    match_second,
                                    sure,
                                )
                                if candidate is None:
                                    continue
                                if best is None or candidate.rank < best.rank:
                                    best = candidate
                if best is not None and best.finding.fingerprint not in candidates:
                    candidates[best.finding.fingerprint] = best
                elif best is not None:
                    existing = candidates[best.finding.fingerprint]
                    if best.rank < existing.rank:
                        candidates[best.finding.fingerprint] = best
    return [item.finding for item in candidates.values()]


def _evaluate_pair(
    listener_name: str,
    first: AttachedRule,
    second: AttachedRule,
    host_first: str,
    host_second: str,
    match_first,
    match_second,
    sure: bool,
) -> _Candidate | None:
    key_first = _decision_key(first, host_first, match_first)
    key_second = _decision_key(second, host_second, match_second)
    winner, loser, win_host, lose_host, win_match, lose_match = (
        (first, second, host_first, host_second, match_first, match_second)
        if key_first <= key_second
        else (second, first, host_second, host_first, match_second, match_first)
    )
    benign = _backends(winner) == _backends(loser)
    factor_key = _tie_key(winner, win_host, win_match)
    tied = _tie_key(winner, win_host, win_match) == _tie_key(loser, lose_host, lose_match)
    reason = _reason(
        _specificity(winner, win_host, win_match),
        _specificity(loser, lose_host, lose_match),
    )
    detail = (
        f"host={host_first} & {host_second}; "
        f"path={match_first.path.kind}:{match_first.path.value} & "
        f"{match_second.path.kind}:{match_second.path.value}"
    )
    common = dict(
        listener=listener_name,
        winner=winner.ident,
        loser=loser.ident,
        reason=reason,
        remedy="Narrow the higher-precedence match, split the listener, or merge the backendRefs.",
        winner_source=winner.route.source,
        loser_source=loser.route.source,
        detail=detail,
    )
    if tied:
        code, title, severity = (
            "RG1003",
            "AMBIGUOUS_PRECEDENCE" if not benign else "REDUNDANT_RULE",
            _severity(sure, benign),
        )
        if benign:
            reason = (
                "Both rules have identical specificity and backendRefs; the overlap is redundant."
            )
        else:
            reason = (
                "Equal specificity and creation timestamp with different backendRefs; "
                "outcome is implementation-defined."
            )
    else:
        covered, cover_sure = matches.route_covers(win_match, lose_match)
        full = cover_sure and _hostnames_cover(winner, loser) and covered
        code = "RG1001" if full else "RG1002"
        title = "SHADOWED_RULE" if full else "PARTIAL_SHADOW"
        severity = _severity(sure and full, benign)
        if not full:
            severity = "WARNING"
        if benign:
            title = "REDUNDANT_RULE"
        else:
            reason += (
                "; the winner covers the entire loser match space"
                if full
                else "; the winner covers only part of the loser match space"
            )
    finding = Finding(
        code,
        severity,
        _certainty(sure),
        title,
        common["listener"],
        common["winner"],
        common["loser"],
        reason,
        common["remedy"],
        common["winner_source"],
        common["loser_source"],
        common["detail"],
    )
    return _Candidate(finding, (_SEVERITY_ORDER[severity], 0 if sure else 1, factor_key))


def _structural_findings(manifests: ManifestSet) -> list[Finding]:
    findings: list[Finding] = []
    gateway_counts = Counter((item.namespace, item.name) for item in manifests.gateways)
    for gateway in manifests.gateways:
        if gateway_counts[(gateway.namespace, gateway.name)] > 1:
            findings.append(
                Finding(
                    "RG1005",
                    "ERROR",
                    "definite",
                    "DUPLICATE_GATEWAY",
                    f"{gateway.namespace}/{gateway.name}",
                    "-",
                    f"{gateway.namespace}/{gateway.name}",
                    "Multiple Gateway objects share the same namespace and name.",
                    "Keep one authoritative Gateway definition per namespace and name.",
                    gateway.source,
                    gateway.source,
                )
            )
        listener_counts = Counter(item.name for item in gateway.listeners)
        for listener in gateway.listeners:
            if listener_counts[listener.name] > 1:
                findings.append(
                    Finding(
                        "RG1008",
                        "ERROR",
                        "definite",
                        "DUPLICATE_LISTENER",
                        listener.qualified,
                        "-",
                        listener.qualified,
                        "Listener names must be unique within a Gateway.",
                        "Rename or merge duplicate listeners.",
                        listener.source,
                        listener.source,
                    )
                )
    for route in manifests.routes:
        for rule in route.rules:
            if not rule.backends:
                findings.append(
                    Finding(
                        "RG1007",
                        "ERROR",
                        "definite",
                        "MISSING_BACKEND",
                        "-",
                        "-",
                        f"{route.namespace}/{route.name}:rule[{rule.index}]",
                        "The rule declares no backendRefs and cannot serve traffic.",
                        "Add at least one backendRef or remove the rule.",
                        route.source,
                        route.source,
                    )
                )
    return findings


def analyze(manifests: ManifestSet) -> AnalysisResult:
    attached, findings = _attach(manifests)
    findings.extend(_conflicts(attached))
    findings.extend(_structural_findings(manifests))
    findings.sort(key=lambda item: (_SEVERITY_ORDER[item.severity], item.code, item.fingerprint))
    stats = dict(manifests.stats)
    stats["attached_rules"] = len(attached)
    stats["findings"] = len(findings)
    stats["errors"] = sum(1 for item in findings if item.severity == "ERROR")
    stats["warnings"] = sum(1 for item in findings if item.severity == "WARNING")
    stats["info"] = sum(1 for item in findings if item.severity == "INFO")
    return AnalysisResult(tuple(findings), stats)


def diff_results(baseline: AnalysisResult, candidate: AnalysisResult) -> AnalysisResult:
    known = {item.fingerprint for item in baseline.findings}
    new = tuple(item for item in candidate.findings if item.fingerprint not in known)
    stats = dict(candidate.stats)
    stats["baseline_findings"] = len(baseline.findings)
    stats["candidate_findings"] = len(candidate.findings)
    stats["new_findings"] = len(new)
    stats["resolved_findings"] = len(known - {item.fingerprint for item in candidate.findings})
    return AnalysisResult(new, stats)


def explain_rule(manifests: ManifestSet, route: str, rule_index: int) -> list[str]:
    target = f"{route}:rule[{rule_index}]"
    attached, _ = _attach(manifests)
    lines = [
        f"Baysöz Labs <baysozlabs@proton.me> — routegate {VERSION}",
        f"Precedence breakdown for {target}",
    ]
    seen: set[str] = set()
    for item in attached:
        if item.ident != target:
            continue
        key = item.listener.qualified
        if key in seen:
            continue
        seen.add(key)
        for hostname in item.hostnames:
            for match in item.rule.matches:
                specificity = _specificity(item, hostname, match)
                lines.append(
                    f"  {key}: host={hostname} host_rank={specificity[0]} "
                    f"path_rank={specificity[1]} headers={-specificity[2]} "
                    f"method={specificity[3]} query={-specificity[4]} "
                    f"timestamp={item.route.creation_stamp or 'unspecified'}"
                )
    if not seen:
        lines.append("  Rule is not attached to any listener; check parentRefs and hostnames.")
    result = analyze(manifests)
    related = [item for item in result.findings if target in {item.winner, item.loser}]
    lines.append(f"Related findings: {len(related)}")
    for finding in related:
        direction = "wins over" if finding.winner == target else "loses to"
        peer = finding.loser if finding.winner == target else finding.winner
        lines.append(
            f"  [{finding.severity}] {finding.code} {target} {direction} {peer}: {finding.reason}"
        )
    lines.append("Attribution: Baysöz Labs <baysozlabs@proton.me>")
    return lines
