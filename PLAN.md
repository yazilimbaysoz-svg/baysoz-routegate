# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate

# PLAN

## Delivered milestones

1. **Research** — mined live GitHub repos/issues on 2026-11-21; excluded every slug in `existing-repos.json`; selected offline Gateway API route-shadowing enforcement.
2. **Core model** — immutable dataclasses for Gateway, Listener, HTTPRoute, Rule, Match, BackendRef and Finding.
3. **Resolver** — parentRef, protocol, namespace selector, allowed-kinds and hostname attachment.
4. **Overlap engine** — hostname wildcards, exact/prefix/regex paths, header/query OR-AND semantics, method constraints.
5. **Precedence engine** — documented specificity order, creation timestamp tie-break, full vs partial shadowing, ambiguity detection.
6. **Reports** — text, JSON and SARIF 2.1.0 with stable fingerprints.
7. **Regression gate** — `diff --baseline ... --candidate ...` emits only newly introduced findings.
8. **Explainability** — `explain` prints each deciding factor for a rule.
9. **Quality gates** — pytest, ruff (`E,F,W,S,B`) and semgrep `p/default`.
10. **Tribunal** — live adversarial execution against malformed, regex-heavy, wildcard-heavy and ambiguous inputs; unanimous pass required before release. **Verdict: UNANIMOUS PASS (11/11 jurors)** on 2026-11-21.

## Non-goals

- No live cluster introspection, no admission controller, no registry access.
- No cryptographic verification of signatures or provenance (covered by dedicated tools).
- No local LLM, no heavy services, no telemetry.

## Release criteria

- Zero test failures, zero ruff findings, zero semgrep findings.
- `--version`, `--help`, all reports and every public file attribute **Baysöz Labs <baysozlabs@proton.me>**.
- Supreme Grand Jury Tribunal returns UNANIMOUS PASS.
- Public repository created under `yazilimbaysoz-svg` with description, topics and pushed source.

Attribution: Baysöz Labs <baysozlabs@proton.me>
