# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate
from __future__ import annotations

from pathlib import Path

from routegate.analysis import analyze, diff_results, explain_rule
from routegate.loader import parse_manifests


def _write(tmp_path: Path, text: str, name: str = "manifests.yaml") -> str:
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")
    return str(target)


GATEWAY = """apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  listeners:
    - name: http
      protocol: HTTP
      port: 80
"""


def route(
    name: str,
    hostname: str,
    path: str,
    backend: str,
    stamp: str = "2026-01-01T00:00:00Z",
    path_type: str = "PathPrefix",
    namespace: str = "default",
) -> str:
    return f"""apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {name}
  namespace: {namespace}
  creationTimestamp: "{stamp}"
spec:
  parentRefs:
    - name: edge
  hostnames:
    - "{hostname}"
  rules:
    - matches:
        - path:
            type: {path_type}
            value: {path}
      backendRefs:
        - name: {backend}
          port: 8080
"""


def test_demo_fixture_detects_full_shadow(demo_path: str):
    result = analyze(parse_manifests([demo_path]))
    shadow = [item for item in result.findings if item.code == "RG1001"]
    assert shadow
    assert all(item.severity == "ERROR" and item.certainty == "definite" for item in shadow)
    assert result.stats["rules"] == 3
    assert result.stats["attached_rules"] == 3
    assert result.stats["errors"] >= 1


def test_analysis_is_deterministic(demo_path: str):
    first = analyze(parse_manifests([demo_path]))
    second = analyze(parse_manifests([demo_path]))
    assert [item.fingerprint for item in first.findings] == [
        item.fingerprint for item in second.findings
    ]


def test_wildcard_label_gap_prevents_conflict(tmp_path: Path):
    source = "\n---\n".join(
        [
            GATEWAY,
            route("wild", "*.example.com", "/", "a", path_type="PathPrefix"),
            route("deep", "shop.eu.example.com", "/", "b", path_type="PathPrefix"),
        ]
    )
    result = analyze(parse_manifests([_write(tmp_path, source)]))
    codes = {item.code for item in result.findings}
    assert "RG1001" not in codes
    assert "RG1002" not in codes
    assert "RG1003" not in codes


def test_regex_conflicts_are_possible_not_definite(tmp_path: Path):
    source = "\n---\n".join(
        [
            GATEWAY,
            route("regex", "shop.example.com", "^/api/.+$", "a", path_type="RegularExpression"),
            route("prefix", "shop.example.com", "/api", "b", path_type="PathPrefix"),
        ]
    )
    result = analyze(parse_manifests([_write(tmp_path, source)]))
    overlap = [item for item in result.findings if item.code in {"RG1001", "RG1002", "RG1003"}]
    assert overlap
    assert all(item.certainty == "possible" for item in overlap)
    assert all(item.severity != "ERROR" for item in overlap)


def test_namespace_selector_blocks_attachment(tmp_path: Path):
    gateway = """apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              tier: edge
"""
    source = "\n---\n".join([gateway, route("orphan", "shop.example.com", "/", "a")])
    result = analyze(parse_manifests([_write(tmp_path, source)]))
    assert any(item.code == "RG1004" for item in result.findings)
    assert result.stats["attached_rules"] == 0


def test_allowed_kinds_blocks_attachment(tmp_path: Path):
    gateway = """apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        kinds:
          - group: gateway.networking.k8s.io
            kind: GRPCRoute
"""
    source = "\n---\n".join([gateway, route("grpc-only", "shop.example.com", "/", "a")])
    result = analyze(parse_manifests([_write(tmp_path, source)]))
    assert any(item.code == "RG1004" for item in result.findings)


def test_structural_findings(tmp_path: Path):
    duplicate_listener = GATEWAY.replace(
        "    - name: http\n      protocol: HTTP\n      port: 80\n",
        "    - name: http\n      protocol: HTTP\n      port: 80\n"
        "    - name: http\n      protocol: HTTP\n      port: 8080\n",
    )
    source = "\n---\n".join(
        [GATEWAY, GATEWAY, duplicate_listener, route("empty", "shop.example.com", "/", "a")]
    )
    source = source.replace("      backendRefs:\n        - name: a\n          port: 8080\n", "")
    result = analyze(parse_manifests([_write(tmp_path, source)]))
    codes = {item.code for item in result.findings}
    assert {"RG1005", "RG1008", "RG1007"}.issubset(codes)


def test_diff_reports_only_new_findings(tmp_path: Path):
    baseline = "\n---\n".join([GATEWAY, route("only", "shop.example.com", "/", "a")])
    candidate = "\n---\n".join(
        [
            GATEWAY,
            route("only", "shop.example.com", "/", "a"),
            route("new", "shop.example.com", "/", "b"),
        ]
    )
    baseline_result = analyze(parse_manifests([_write(tmp_path, baseline, "base.yaml")]))
    candidate_result = analyze(parse_manifests([_write(tmp_path, candidate, "cand.yaml")]))
    delta = diff_results(baseline_result, candidate_result)
    assert delta.stats["new_findings"] == len(delta.findings)
    assert all(item.code in {"RG1001", "RG1002", "RG1003"} for item in delta.findings)


def test_explain_rule_reports_factors(demo_path: str):
    lines = explain_rule(parse_manifests([demo_path]), "edge/legacy-wide", 0)
    text = "\n".join(lines)
    assert "host_rank" in text
    assert "Baysöz Labs <baysozlabs@proton.me>" in text
