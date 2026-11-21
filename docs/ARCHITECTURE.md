# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate

# Architecture

## Scope

`routegate` answers one question deterministically: *given a set of Gateway API manifests, can any accepted HTTPRoute rule be preempted by another rule before traffic reaches its backend?*

It is a pure function of local files. No API server, no DNS, no registry, no telemetry, no LLM.

## Pipeline

1. **Ingestion** (`loader.py`): resolves files/directories, parses multi-document YAML/JSON with `yaml.safe_load_all`, validates types, normalizes hostnames, compiles regexes and builds typed objects in `model.py`.
2. **Attachment** (`analysis._attach`): for each route, tests every listener for parentRef match, protocol compatibility, namespace policy (`Same`, `Selector` with matchLabels/matchExpressions, `All`), allowed kinds, and hostname intersection. Unattached routes become RG1004 findings.
3. **Overlap**: for each listener, every pair of attached rules is compared across hostname pairs and match alternatives. A match intersects only if hostname, path, headers (per-name OR, across-names AND), query params and method all intersect.
4. **Precedence**: a deterministic key is computed as `(hostname rank, path rank, -header count, method present, -query count, creation timestamp, input order, identity)`. The lower key wins. Equal specificity *and* equal creation timestamp with different backends yields RG1003.
5. **Classification**: if the winner's hostname and match space cover the loser's entire space, RG1001 (error); otherwise RG1002 (warning). Identical backend sets downgrade the finding to INFO (`REDUNDANT_RULE`). Regex-derived overlaps are marked `possible` and capped at warning.
6. **Reporting** (`report.py`): text for humans, JSON for automation, SARIF 2.1.0 for GitHub Code Scanning.

## Why hostname first

Gateway API precedence places hostname specificity ahead of path specificity. A wildcard host with an exact path **loses** to an exact host with a prefix path. This is the single most counter-intuitive case the tool detects, and the demo fixture exercises it.

## Path model

| Kind | Set semantics | Coverage |
| --- | --- | --- |
| `Exact` | single path | equal exact only |
| `PathPrefix` | string prefix | prefix-of-prefix, prefix-of-exact |
| `RegularExpression` | full-match regex | identical pattern, or regex full-matching an exact path |

Regex vs prefix intersections are conservative: the tool reports a possible overlap rather than claiming certainty. This avoids both false negatives and fake precision.

## Determinism guarantees

- Inputs are sorted by resolved path; manifests are processed in document order.
- All findings are sorted by severity, code and fingerprint.
- Fingerprints exclude message text and timestamps, so `diff` reports only semantic regressions.
- No wall-clock time, randomness, environment data or network state enters analysis.

## Complexity

For `R` attached rules on a listener, `H` hostnames and `M` match alternatives per rule, pairwise analysis is `O(R² · H² · M²)`. Typical manifests are small; worst case is bounded by input validation limits in CI. No cluster state is fetched.

## Module map

| Module | Responsibility |
| --- | --- |
| `model.py` | Immutable dataclasses, version and attribution. |
| `loader.py` | Parsing, validation, normalization, typed construction. |
| `hostnames.py` | Wildcard intersection, containment, specificity. |
| `paths.py` | Path set intersection and coverage. |
| `matches.py` | Header/query/method semantics. |
| `analysis.py` | Attachment, precedence, findings, diff, explain. |
| `report.py` | Text/JSON/SARIF renderers. |
| `cli.py` | Argparse interface and exit-code policy. |

## Extension points

- Add `GRPCRoute` by extending `loader` parsing and attachment compatibility; the overlap engine already operates on typed matches.
- Add CEL-based policy by attaching an external evaluator to the finding set, not by mutating core analysis.
- Add new output formats in `report.render`.

Attribution: Baysöz Labs <baysozlabs@proton.me>
