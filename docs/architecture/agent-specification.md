# Agent specification

The platform is itself an autonomous agent: it decides, without a person in
the loop, whether a release may proceed. This document states its mandate in
the same terms the portfolio requires of every agent.

## Role and mission

- **Purpose:** provide a repeatable, evidence-backed answer to "is this
  agent release safe enough to promote?"
- **Business objective:** let teams release agents frequently without
  accepting unmeasured risk or waiting on manual review for routine builds.
- **Protected resources:** release decisions, signed evaluation evidence,
  target registrations, the audit chain and its signing key.
- **Operating boundaries:** sends only benign synthetic probes; never sends
  realistic attack content; never deploys, modifies or rolls back the agent
  under test; never approves its own decisions.
- **Delegated responsibility:** thresholds are owned by AI governance
  (`policies/release-gate.yaml`), decision logic by release management
  (`policies/release-decision.yaml`), tool rules by the agent's platform team
  (`policies/target-tool-policy.yaml`); all are versioned, digested and
  recorded in every report.

## Delegated scope

| Allowed autonomously | Disallowed | Risk | Escalation |
|---|---|---|---|
| Expand suites, send probes to registered, allow-listed targets | Probe hosts outside `CRT_TARGET_ALLOWED_HOSTS`, metadata or link-local addresses | Moderate | Registration refused (422), audited |
| Return `pass` when every category is within threshold with enough evidence | Pass a category with too few conclusive probes or too many target errors | High | `fail` with `deny-insufficient-evidence` |
| Return `fail` | Override a deny rule | — | Requires a policy change through CODEOWNERS review |
| Return `require_approval` for high/critical-risk production releases or advisory findings | Approve; let the requester or a pipeline approve | Critical | Release approver (two-person rule) |
| Use an LLM judge as advisory | Let an uncalibrated LLM judge fail or pass a probe | High | Operator calibration (`kappa >= 0.6`) |

## Objectives

| Type | Definition | Target |
|---|---|---|
| SLO availability | Non-5xx share of API requests | 99.9% over 30 days |
| SLO latency | p99 of read endpoints (run polling, decisions) | < 250 ms |
| SLO freshness | Queued run to completed for the 394-probe baseline suite against a target answering within 2 s | < 30 min |
| SLI | `crt:request_errors:ratio_5m`, `crt_http_request_duration_seconds`, `crt_runs_total`, `crt_probes_total` | Prometheus |
| KPI | Share of production agent releases gated by this platform | 100% |
| KPI | Releases blocked that later needed a hotfix for a measured category | tracked per quarter |
| KPI | Measurement accuracy: configured weakness rate of the reference agent inside the reported 95% Wilson interval | verified in CI on every commit |
| Completion | A gate decision is complete when its report is signed and its digest is in the audit chain | enforced: audit failure fails the request |

## Permissions

| Mechanism | Use |
|---|---|
| RBAC | Roles `redteam-operator`, `redteam-auditor`, `release-approver`, `release-pipeline` from the enterprise IdP or a CI issuer's `default_roles` |
| ABAC | `policies/platform-access.yaml`: deny self-approval (`subject.id eq_attr resource.requested_by`), deny non-human approval |
| Agent identity | Agent callers present agent-identity-fabric credentials; the fabric authorizes `redteam.*` actions via `/v1/authorize` |
| OAuth / OIDC | Bearer JWTs verified against issuer JWKS (RS256, ES256, EdDSA), audience and time checks against the injected clock |
| Workload identity | GKE Workload Identity (GCP), IRSA (AWS), Azure Workload ID for cloud access; a projected service-account token for the fabric jwt-bearer grant |

## Inputs and outputs

| Contract | Schema |
|---|---|
| Suite (input, Git-reviewed) | `schemas/suite.schema.json` |
| Target registration | `schemas/target-registration.request.schema.json` |
| Run request / run | `schemas/run.request.schema.json`, `schemas/run.response.schema.json` |
| Probe sent to a target | `schemas/agent-invocation.request.schema.json` |
| Reply expected from a target | `schemas/agent-reply.response.schema.json` |
| Gate decision / signed report | `schemas/gate-decision.response.schema.json`, `schemas/signed-report.schema.json` |
| Gate thresholds | `schemas/release-gate.policy.schema.json` |

Validation: inputs reject unknown fields; templates accept only `{name}`
placeholders (no attribute access or format specs); labels must be valid
OWASP LLM 2025 / MITRE ATLAS identifiers; target replies are size-bounded
and validated; URLs pass the egress guard.

Provenance: every run records suite name, version and digest, seed, target
version and requester; every report records gate and decision policy names,
versions and digests, matched rules, the platform version and the LLM judge
calibration state.

Audit metadata: actor, action, resource, outcome, correlation ID, details,
sequence, previous hash, hash, Ed25519 signature and key ID for every event
(`target.register`, `run.create`, `run.finish`, `gate.evaluate`,
`gate.approve`, `judge.calibrate`, `mcp.*`, `access.denied`).
