# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

import json
from pathlib import Path

import pytest

from routegate.cli import main


def test_version_and_help_attribute_baysöz_labs(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as version:
        main(["--version"])
    assert version.value.code == 0
    assert "Baysöz Labs <baysozlabs@proton.me>" in capsys.readouterr().out

    with pytest.raises(SystemExit) as help_exit:
        main(["--help"])
    assert help_exit.value.code == 0
    assert "Baysöz Labs <baysozlabs@proton.me>" in capsys.readouterr().out


def test_scan_text_gate_exits_nonzero(demo_path: str, capsys: pytest.CaptureFixture[str]):
    code = main(["scan", demo_path])
    output = capsys.readouterr().out
    assert code == 1
    assert "SHADOWED_RULE" in output
    assert "Baysöz Labs <baysozlabs@proton.me>" in output


def test_scan_json_and_sarif(demo_path: str, capsys: pytest.CaptureFixture[str]):
    assert main(["scan", demo_path, "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"
    assert payload["findings"]

    assert main(["scan", demo_path, "--format", "sarif"]) == 1
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert (
        sarif["runs"][0]["tool"]["driver"]["organization"] == "Baysöz Labs <baysozlabs@proton.me>"
    )
    assert sarif["runs"][0]["results"]


def test_scan_fail_on_none_and_quiet(demo_path: str, capsys: pytest.CaptureFixture[str]):
    assert main(["scan", demo_path, "--fail-on", "none", "--quiet"]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_scan_writes_output_file(demo_path: str, tmp_path: Path):
    target = tmp_path / "report.sarif"
    assert main(["scan", demo_path, "--format", "sarif", "--output", str(target)]) == 1
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_diff_and_explain_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    base = tmp_path / "base.yaml"
    candidate = tmp_path / "candidate.yaml"
    gateway = """apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
spec:
  listeners:
    - name: http
      protocol: HTTP
      port: 80
"""
    route = """apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {name}
spec:
  parentRefs:
    - name: edge
  hostnames:
    - shop.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: {backend}
          port: 80
"""
    base.write_text(gateway + "---\n" + route.format(name="only", backend="a"), encoding="utf-8")
    candidate.write_text(
        gateway
        + "---\n"
        + route.format(name="only", backend="a")
        + "---\n"
        + route.format(name="new", backend="b"),
        encoding="utf-8",
    )
    assert main(["diff", "--baseline", str(base), "--candidate", str(candidate)]) == 1
    assert "AMBIGUOUS_PRECEDENCE" in capsys.readouterr().out

    assert main(["explain", str(candidate), "--route", "default/new", "--rule", "0"]) == 0
    assert "Precedence breakdown" in capsys.readouterr().out


def test_invalid_manifest_returns_input_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    broken = tmp_path / "broken.yaml"
    broken.write_text(
        "apiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\nmetadata: [oops\n",
        encoding="utf-8",
    )
    assert main(["scan", str(broken)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "input error" in captured.err
    assert "Baysöz Labs <baysozlabs@proton.me>" in captured.err


def test_invalid_regex_is_rejected(tmp_path: Path):
    broken = tmp_path / "regex.yaml"
    broken.write_text(
        """apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
spec:
  listeners:
    - name: http
      protocol: HTTP
      port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: bad
spec:
  parentRefs:
    - name: edge
  rules:
    - matches:
        - path:
            type: RegularExpression
            value: "("
""",
        encoding="utf-8",
    )
    assert main(["scan", str(broken)]) == 2
