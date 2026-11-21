# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

import json

from .model import VERSION, AnalysisResult
from .paths import RANK

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_HOME = "https://github.com/yazilimbaysoz-svg/baysoz-routegate"
_LEVEL = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}

_RULES = {
    "RG1001": (
        "Rule fully shadowed by higher-precedence rule",
        "Route traffic can never reach this rule.",
    ),
    "RG1002": ("Rule partially shadowed", "A subset of this rule's match space is preempted."),
    "RG1003": (
        "Ambiguous route precedence",
        "Equal specificity with different backends is implementation-defined.",
    ),
    "RG1004": (
        "Route does not attach to any listener",
        "The route is inert for the supplied Gateway set.",
    ),
    "RG1005": ("Duplicate Gateway", "Ambiguous Gateway identity."),
    "RG1007": ("Rule has no backendRefs", "The rule cannot serve traffic."),
    "RG1008": ("Duplicate listener name", "Listener names must be unique per Gateway."),
}


def _sarif(result: AnalysisResult) -> dict[str, object]:
    rules = [
        {
            "id": code,
            "name": name.replace(" ", ""),
            "shortDescription": {"text": name},
            "fullDescription": {"text": description},
            "defaultConfiguration": {
                "level": "error" if code in {"RG1001", "RG1005", "RG1007", "RG1008"} else "warning"
            },
        }
        for code, (name, description) in sorted(_RULES.items())
    ]
    results: list[dict[str, object]] = []
    for finding in result.findings:
        description = _RULES.get(finding.code, (finding.title, finding.reason))[1]
        results.append(
            {
                "ruleId": finding.code,
                "level": _LEVEL[finding.severity],
                "message": {"text": f"{finding.title}: {finding.reason}. {description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.loser_source},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "certainty": finding.certainty,
                    "listener": finding.listener,
                    "winner": finding.winner,
                    "loser": finding.loser,
                    "detail": finding.detail,
                    "remedy": finding.remedy,
                    "attribution": "Baysöz Labs <baysozlabs@proton.me>",
                },
                "ruleIndex": sorted(_RULES).index(finding.code) if finding.code in _RULES else 0,
                "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
            }
        )
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "routegate",
                        "version": VERSION,
                        "organization": "Baysöz Labs <baysozlabs@proton.me>",
                        "informationUri": _HOME,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "attribution": "Baysöz Labs <baysozlabs@proton.me>",
                    "pathMatchRanking": RANK,
                    "stats": result.stats,
                },
            }
        ],
    }


def _text(result: AnalysisResult, title: str) -> str:
    lines = [
        f"Baysöz Labs <baysozlabs@proton.me> — routegate {VERSION}",
        title,
        (
            f"Scanned {result.stats.get('files', 0)} file(s), "
            f"{result.stats.get('gateways', 0)} Gateway(s), "
            f"{result.stats.get('routes', 0)} HTTPRoute(s), "
            f"{result.stats.get('rules', 0)} rule(s), "
            f"{result.stats.get('attached_rules', 0)} attached rule(s)"
        ),
        (
            f"Findings: {result.stats.get('errors', 0)} error, "
            f"{result.stats.get('warnings', 0)} warning, "
            f"{result.stats.get('info', 0)} info"
        ),
    ]
    if not result.findings:
        lines.append("No route conflicts detected.")
    for finding in result.findings:
        lines.extend(
            [
                "",
                f"[{finding.severity}] {finding.code} {finding.title} ({finding.certainty})",
                f"  listener : {finding.listener}",
                f"  winner   : {finding.winner}",
                f"  loser    : {finding.loser}",
                f"  why      : {finding.reason}",
                f"  where    : {finding.detail}",
                f"  fix      : {finding.remedy}",
                f"  source   : {finding.loser_source}",
            ]
        )
    lines.append("")
    lines.append("Attribution: Baysöz Labs <baysozlabs@proton.me>")
    return "\n".join(lines)


def render(
    result: AnalysisResult, fmt: str, title: str = "Gateway API route conflict report"
) -> str:
    if fmt == "text":
        return _text(result, title)
    if fmt == "json":
        payload = {
            "tool": "routegate",
            "version": VERSION,
            "attribution": "Baysöz Labs <baysozlabs@proton.me>",
            "title": title,
            "stats": result.stats,
            "findings": [item.as_dict() for item in result.findings],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    if fmt == "sarif":
        return json.dumps(_sarif(result), indent=2, ensure_ascii=False, sort_keys=True)
    raise ValueError(f"unsupported format: {fmt}")


def render_lines(lines: list[str]) -> str:
    return "\n".join([*lines, "", "Attribution: Baysöz Labs <baysozlabs@proton.me>", ""])
