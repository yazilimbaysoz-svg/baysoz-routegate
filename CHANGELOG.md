# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate

# Changelog

## 1.0.0 — 2026-11-21

- Initial release by Baysöz Labs <baysozlabs@proton.me>.
- Offline Gateway API attachment resolver: parentRefs, namespace selectors, allowed kinds, protocol and hostname compatibility.
- Deterministic overlap and precedence engine for hostname, path, header, query and method matches.
- Findings RG1001–RG1008 with definite/possible certainty and SARIF 2.1.0 output.
- Regression gate via `diff --baseline ... --candidate ...`.
- Rule explainability via `explain --route ... --rule ...`.
- Quality gates: pytest, ruff, semgrep.

Attribution: Baysöz Labs <baysozlabs@proton.me>
