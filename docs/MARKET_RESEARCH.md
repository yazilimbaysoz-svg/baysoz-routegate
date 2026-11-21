# Baysöz Labs <baysozlabs@proton.me> — baysoz-routegate

# Market research — 2026-11-21

## Method

Live ecosystem mining was performed on 2026-11-21 with `gh search repos` and `gh search issues` using the authenticated `yazilimbaysoz-svg` account. Queries covered platform engineering, supply-chain security, Kubernetes validation, Gateway API, SBOM verification, SLSA provenance, Helm schemas and image digest pinning. Repositories already present in `existing-repos.json` were excluded from the product choice.

## Observed high-star anchors

| Repository | Stars | Signal |
| --- | --- | --- |
| `yannh/kubeconform` | 3266 | Manifest validation is a mature, high-demand category. |
| `KusionStack/karpor` | 1725 | Kubernetes platform engineering visualization is mainstream. |
| `kbst/terraform-kubestack` | 714 | GitOps-driven platform stacks need pre-apply safety. |
| `fluxcd/flux-schema` | 50 | Schema and CEL validation is being pushed into GitOps workflows. |

Cutting-edge categories were also visible: `in-toto/attestation` issues on ML-DSA signing and Python attribute reports, `notaryproject/ratify` issues on CycloneDX SBOM verification and SLSA provenance, and `sigstore/policy-controller` SLSA verification requests.

## Live pain points mined from open issues

1. **Digest pinning is a cross-repository epidemic.** Open issues in `LibreChat-AI/LibreChat`, `gravitational/teleport`, `shopsys/helm`, `CyberXdefend/VaultShip`, `konflux-ci/tekton-integration-catalog` and others ask for digest pinning, digest propagation and policy enforcement. This confirms platform teams want pre-apply gates, not more dashboards.
2. **Provenance and SBOM verification are fragmented.** `kusari-oss/waybill` asks for in-toto subject extraction to close `artifactsFrom` chains; `millsks/pixi-sbom` asks for `--verify-sbom` gating; `notaryproject/ratify` and `sigstore/policy-controller` have open SLSA support requests. The need for offline deterministic verification is real, but this is already crowded with signature-focused tools and overlaps existing Baysöz Labs work on action lockfiles.
3. **Schema validation is necessary but insufficient.** `camunda/camunda-platform-helm` debates strict values validation, `krateo-platformops/core-provider` reports a chart inspector burying Helm errors, and `Digitalist-Open-Cloud/matomo-kubernetes` reports schema rejection drift. Schema checks prove *shape*, not *runtime routing semantics*.
4. **Platform gates are gravitating to SARIF.** Fresh repositories in the same window (`planradius`, `OpenTrustBench`, `mcpxray`, `AgentShield`) all use SARIF plus CI gating. This is now the expected integration contract.

## The uncovered gap: Gateway API route shadowing

Kubernetes Gateway API deliberately delegates conflict resolution to implementations. Two accepted `HTTPRoute` objects can overlap on hostname, path, headers, query and method. The winner is decided by a precedence order (hostname specificity, path specificity, header count, method, query count, creation timestamp) that most engineers never simulate before `kubectl apply`. Result: a canary rule silently receives zero traffic, or an older wildcard route captures a new exact endpoint.

Existing tooling does not close this gap:

- `kubeconform` and `flux-schema` validate structure and CEL, not cross-object overlap/precedence.
- Controller implementations (Envoy Gateway, Istio, NGINX Gateway Fabric) resolve conflicts at runtime, after deployment.
- Generic policy engines require a live cluster, a gatekeeper/kyverno install or Rego/Cedar expertise.
- Existing Baysöz Labs projects cover JWT confusion, Terraform blast radius, OTel config/cardinality, ATR parity, Action lockfiles, env drift and log masking — none address L7 routing semantics.

`routegate` is therefore a distinct, high-value, offline, deterministic pre-apply gate: it resolves attachment to listeners, computes hostname/path/header/query/method intersections, applies a documented precedence model, classifies full vs partial shadowing vs ambiguity, and emits SARIF for CI enforcement. It is a Python 3.13 library and CLI, not a service, and needs no cluster, registry, LLM or network access.

## Positioning statement

Policy gates already protect infrastructure shape; `routegate` protects **traffic reachability** — the last mile between a valid manifest and the request that must reach its backend.

Attribution: Baysöz Labs <baysozlabs@proton.me>
