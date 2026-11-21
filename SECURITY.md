# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate

# Security policy

## Reporting

Report vulnerabilities privately to **Baysöz Labs <baysozlabs@proton.me>**. Do not open a public issue for exploitable defects. Include reproduction manifests, affected version and impact.

## Trust model

`routegate` is an offline static analyser. It reads untrusted YAML/JSON and never executes manifests, contacts a cluster or resolves external references. Input files are treated as hostile data.

## Hardening decisions

- `yaml.safe_load_all` only; no arbitrary object construction.
- All regexes supplied by manifests are compiled and validated before analysis; analysis uses `fullmatch`, never `eval`/`exec`.
- Ports, match types, selector operators, paths and hostnames are validated during ingestion; malformed documents produce exit code 2 with no traceback.
- No subprocesses, sockets, shell commands, environment-secret reads or pickle deserialization.
- Findings are deterministic; adversarial inputs cannot suppress a finding through timestamp spoofing because creation timestamps only break exact ties, never override specificity.
- Regex-derived overlaps are conservative (`possible`, warning ceiling), preventing false certainty in security decisions.

## CI enforcement

Use `routegate scan ... --format sarif --output routegate.sarif --fail-on error` and upload the SARIF to code scanning. Use `routegate diff --baseline ... --candidate ... --fail-on error` to gate pull requests on newly introduced conflicts only.

## Supported versions

Security fixes are applied to the latest 1.x release. Python 3.13+ is required.

Attribution: Baysöz Labs <baysozlabs@proton.me>
