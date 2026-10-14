# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-14

### Added

- Versioned YAML scenario suites with schema validation, content digests and
  safe `{name}`-only templating; `agent-baseline@2026.10.0` (394 probes,
  five categories).
- Deterministic expansion: parameter grids, seeded sampling, repeats,
  HMAC-derived `CANARY-<uuid>` markers and session ids.
- Target adapters for HTTP agent endpoints, MCP servers (official `mcp`
  client) and A2A agents (`message/send`, `tasks/get` polling); independent
  trace endpoints; in-process reference agents with configurable weaknesses.
- Judges: marker leakage across encodings and tool arguments, forbidden tool
  execution, tool-policy violations, approval bypass; optional LLM rubric
  judge behind ContentGuard, advisory until calibrated with Cohen's kappa.
- Scoring with Wilson intervals and scenario-cluster bootstrap; regression
  detection with Newcombe intervals and scenario flips.
- Release gate: per-category thresholds on the Wilson upper bound,
  insufficient-evidence detection, PolicyEngine decision, two-person
  approval, Ed25519-signed reports and signed audit chain.
- REST API, MCP tools, A2A agent card and JSON-RPC endpoint; identity via
  enterprise OIDC, GitHub Actions OIDC and agent-identity-fabric.
- Reusable composite GitHub Action (`action.yml`) with a standard-library client.
- Helm chart, Kubernetes namespace and secret sync, Terraform for GCP, AWS and Azure.
- CI: lint, types, SAST, contract drift, tests (unit, security, chaos,
  performance, e2e, PostgreSQL integration), pip-audit, Helm/kubeconform,
  Terraform validate, Trivy, Syft, Grype, Semgrep, container smoke test and
  an end-to-end run of the composite action against the built image.
