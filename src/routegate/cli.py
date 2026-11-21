# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analysis import analyze, diff_results, explain_rule
from .loader import ManifestError, parse_manifests
from .model import ATTRIBUTION, VERSION
from .report import render, render_lines

_LEVELS: dict[str, int] = {"ERROR": 3, "WARNING": 2, "INFO": 1}
_EPILOG = f"{ATTRIBUTION} — offline Gateway API route-conflict enforcement."


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="routegate",
        description="Deterministic offline Gateway API route conflict and shadowing gate.",
        epilog=_EPILOG,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"routegate {VERSION} — Baysöz Labs <baysozlabs@proton.me>",
        help="show version and Baysöz Labs attribution",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="analyze manifests and emit a report",
        description="Analyze Kubernetes Gateway and HTTPRoute manifests.",
        epilog=_EPILOG,
    )
    scan.add_argument("inputs", nargs="+", help="YAML/JSON files or directories")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--output", help="write report to a file instead of stdout")
    scan.add_argument("--fail-on", choices=("error", "warning", "info", "none"), default="error")
    scan.add_argument("--quiet", action="store_true", help="suppress report output")

    diff = subparsers.add_parser(
        "diff",
        help="report conflicts introduced relative to a baseline",
        description="Compare two manifest sets and emit only newly introduced findings.",
        epilog=_EPILOG,
    )
    diff.add_argument("--baseline", nargs="+", required=True, help="baseline manifest paths")
    diff.add_argument("--candidate", nargs="+", required=True, help="candidate manifest paths")
    diff.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    diff.add_argument("--output", help="write report to a file instead of stdout")
    diff.add_argument("--fail-on", choices=("error", "warning", "info", "none"), default="error")
    diff.add_argument("--quiet", action="store_true", help="suppress report output")

    explain = subparsers.add_parser(
        "explain",
        help="show precedence factors for a route rule",
        description="Explain why a specific rule wins or loses.",
        epilog=_EPILOG,
    )
    explain.add_argument("inputs", nargs="+", help="YAML/JSON files or directories")
    explain.add_argument("--route", required=True, help="route as namespace/name")
    explain.add_argument("--rule", required=True, type=int, help="rule index")
    explain.add_argument("--output", help="write explanation to a file instead of stdout")

    return parser


def _emit(text: str, output: str | None, quiet: bool) -> None:
    if quiet:
        return
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        return
    sys.stdout.write(text + "\n")


def _gated(result, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = _LEVELS[fail_on.upper()]
    return any(_LEVELS[item.severity] >= threshold for item in result.findings)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            result = analyze(parse_manifests(args.inputs))
            title = "Gateway API route conflict report"
        elif args.command == "diff":
            result = diff_results(
                analyze(parse_manifests(args.baseline)), analyze(parse_manifests(args.candidate))
            )
            title = "New Gateway API route conflicts"
        else:
            manifests = parse_manifests(args.inputs)
            _emit(render_lines(explain_rule(manifests, args.route, args.rule)), args.output, False)
            return 0
        _emit(render(result, args.format, title), args.output, args.quiet)
        return 1 if _gated(result, args.fail_on) else 0
    except ManifestError as exc:
        sys.stderr.write(f"routegate: input error: {exc}\n{ATTRIBUTION}\n")
        return 2
    except OSError as exc:
        sys.stderr.write(f"routegate: I/O error: {exc}\n{ATTRIBUTION}\n")
        return 2
