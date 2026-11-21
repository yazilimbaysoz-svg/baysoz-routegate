# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate

# routegate

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-routegate/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-routegate/actions/workflows/ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Static: ruff + semgrep](https://img.shields.io/badge/static-ruff%20%2B%20semgrep-informational.svg)](.github/workflows/ci.yml)
[![Attribution](https://img.shields.io/badge/by-Bays%C3%B6z%20Labs-baysozlabs%40proton.me.svg)](mailto:baysozlabs@proton.me)

**Offline Kubernetes Gateway API route-conflict and shadowing gate with deterministic precedence resolution and SARIF CI enforcement.**

Maintained by **Baysöz Labs — baysozlabs@proton.me**. Zero services, zero telemetry, zero local LLMs. Runs entirely on local manifests.

## Why

Gateway API route precedence is a silent traffic-correctness boundary. When an exact-host rule and a wildcard-host rule overlap, or a path prefix and a regex compete, the API server accepts both manifests and the data plane quietly chooses one. `routegate` detects those overlaps **before** apply, explains the deciding factor, and fails CI on newly introduced conflicts.

## Install

```bash
uv venv
uv pip install -e .
routegate --version
```

Python 3.13+ and `uv` are the only requirements. The sole runtime dependency is PyYAML.

## CLI

```bash
routegate scan path/to/manifests --format text --fail-on error
routegate scan path/to/manifests --format sarif --output routegate.sarif
routegate diff --baseline ./main --candidate ./pr --format json
routegate explain tests/fixtures/demo.yaml --route edge/legacy-wide --rule 0
```

### Real CLI output

_Generated from `tests/fixtures/demo.yaml` with `routegate scan tests/fixtures/demo.yaml`._

```text
Baysöz Labs <baysozlabs@proton.me> — routegate 1.0.0
Gateway API route conflict report
Scanned 1 file(s), 1 Gateway(s), 3 HTTPRoute(s), 3 rule(s), 3 attached rule(s)
Findings: 1 error, 1 warning, 0 info

[ERROR] RG1001 SHADOWED_RULE (definite)
  listener : edge/public:http
  winner   : edge/canonical:rule[0]
  loser    : edge/legacy-wide:rule[0]
  why      : hostname specificity favours the winner ((0, -3) vs (1, -3)); the winner covers the entire loser match space
  where    : host=shop.example.com & *.example.com; path=PathPrefix:/api & Exact:/api/health
  fix      : Narrow the higher-precedence match, split the listener, or merge the backendRefs.
  source   : /home/runner/work/_temp/baysoz-new-project/tests/fixtures/demo.yaml

[WARNING] RG1002 PARTIAL_SHADOW (definite)
  listener : edge/public:http
  winner   : edge/checkout:rule[0]
  loser    : edge/canonical:rule[0]
  why      : path specificity favours the winner ((0, -9, '/api/cart') vs (1, -4, '/api')); the winner covers only part of the loser match space
  where    : host=shop.example.com & shop.example.com; path=PathPrefix:/api & Exact:/api/cart
  fix      : Narrow the higher-precedence match, split the listener, or merge the backendRefs.
  source   : /home/runner/work/_temp/baysoz-new-project/tests/fixtures/demo.yaml

Attribution: Baysöz Labs <baysozlabs@proton.me>
```

## Library

```python
from routegate.analysis import analyze
from routegate.loader import parse_manifests
from routegate.report import render

result = analyze(parse_manifests(["tests/fixtures/demo.yaml"]))
print(render(result, "sarif"))
```

## Architecture

```text
YAML/JSON manifests
        │
        ▼
loader.py ──► typed model (Gateway, Listener, HTTPRoute, Rule, Match)
        │
        ▼
analysis.py ──► attachment resolver ──► overlap engine ──► precedence engine
        │                                                       │
        ▼                                                       ▼
diffing (regression gate)                              report.py (text / JSON / SARIF)
```

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · research: [docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md) · plan: [PLAN.md](PLAN.md) · security: [SECURITY.md](SECURITY.md) · changes: [CHANGELOG.md](CHANGELOG.md).

## Rule codes

| Code | Meaning | Default |
| --- | --- | --- |
| RG1001 | Rule fully shadowed by a higher-precedence rule | error |
| RG1002 | Rule partially shadowed | warning |
| RG1003 | Equal precedence, different backends (ambiguous) | error |
| RG1004 | Route attaches to no listener | warning |
| RG1005 | Duplicate Gateway identity | error |
| RG1007 | Rule has no backendRefs | error |
| RG1008 | Duplicate listener name | error |

Regex-based overlaps are reported as `possible` and capped at warning; deterministic matches are reported as `definite`.

## Quality gates

```bash
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

## Attribution

Baysöz Labs <baysozlabs@proton.me> — https://github.com/yazilimbaysoz-svg
