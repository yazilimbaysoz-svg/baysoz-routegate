# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

import json

from routegate.model import AnalysisResult, Finding
from routegate.report import render, render_lines


def _result() -> AnalysisResult:
    finding = Finding(
        "RG1001",
        "ERROR",
        "definite",
        "SHADOWED_RULE",
        "default/edge:http",
        "default/main:rule[0]",
        "default/legacy:rule[0]",
        "hostname specificity favours the winner",
        "Narrow the match.",
        "main.yaml",
        "legacy.yaml",
    )
    return AnalysisResult((finding,), {"files": 2, "errors": 1, "warnings": 0, "info": 0})


def test_text_report_contains_attribution():
    text = render(_result(), "text")
    assert "Baysöz Labs <baysozlabs@proton.me>" in text
    assert "SHADOWED_RULE" in text


def test_json_report_is_stable():
    first = render(_result(), "json")
    second = render(_result(), "json")
    assert first == second
    assert json.loads(first)["findings"][0]["code"] == "RG1001"


def test_sarif_report_structure():
    sarif = json.loads(render(_result(), "sarif"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "RG1001"
    assert sarif["runs"][0]["properties"]["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"


def test_render_lines_appends_attribution():
    assert "Baysöz Labs <baysozlabs@proton.me>" in render_lines(["header"])
