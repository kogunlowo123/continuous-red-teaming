# Architecture

## Business problem

Enterprises now release AI agents the way they release services: often, and
with changes to prompts, models, tools and retrieval sources that each alter
behaviour. Security reviews and one-off red-team exercises are point-in-time;
they do not tell a release manager whether build 412 still keeps internal
identifiers internal, still declines forbidden tools, and still waits for a
person before disabling an account. Without a repeatable, statistically
honest test with signed evidence, teams either slow releases down with
manual review or ship blind.

This platform turns agent safety validation into a release-engineering gate:
the same versioned probe suites run on every candidate, results are scored
with confidence intervals, compared with the last releasable version, and a
policy decides `pass`, `fail` or `require_approval`. The decision ships with
a signed report.

## System context (C4 level 1)

```mermaid
C4Context
  title Continuous Red Teaming
  Person(operator, "Red-team operator", "Registers targets, authors suites")
  Person(approver, "Release approver", "Signs off gated releases")
  System(crt, "Continuous Red Teaming", "Probe suites, judges, scoring, release gate, signed reports")
  System_Ext(ci, "CI/CD pipelines", "GitHub Actions composite action")
  System_Ext(agents, "Agents under test", "HTTP, MCP or A2A endpoints")
  System_Ext(fabric, "Agent identity fabric", "Agent credentials, /v1/authorize")
  System_Ext(idp, "Enterprise IdP", "OIDC for people")
  System_Ext(llm, "Model providers", "Optional LLM judge (Vertex AI Gemini, Claude)")
  System_Ext(siem, "SIEM / evidence store", "Audit chains, metrics, traces")
  Rel(ci, crt, "Start run, evaluate gate", "GitHub OIDC")
  Rel(operator, crt, "Targets, suites, calibration", "OIDC")
  Rel(approver, crt, "Approve", "OIDC")
  Rel(crt, agents, "Benign probes", "HTTPS")
  Rel(crt, fabric, "Authorize agent callers; own credential")
  Rel(crt, idp, "JWKS")
  Rel(crt, llm, "Rubric judging (CONFIDENTIAL max)")
  Rel(crt, siem, "Signed audit chain, Prometheus, OTLP")
```

## Containers (C4 level 2)

```mermaid
flowchart LR
  subgraph ns[Kubernetes namespace agent-validation]
    api[FastAPI service<br/>REST + /mcp/ + /a2a<br/>StatefulSet x2..8]
    pvc[(Per-replica audit volume)]
  end
  db[(Managed PostgreSQL<br/>targets, runs, probe results, decisions)]
  sm[Secret manager<br/>DB URL, audit signing key, provider vars]
  worm[(Retention-locked bucket<br/>audit chains)]
  otel[OTel collector]
  targets[Agents under test]
  api --> db
  sm -- External Secrets --> api
  api --> pvc -- log shipper --> worm
  api --> otel
  api -- probes --> targets
```

## Components (C4 level 3)

| Layer | Module | Responsibility |
|---|---|---|
| API | `api.routes`, `api.app` | REST contract, authentication, authorization, correlation IDs, metrics, OAuth-style errors |
| API | `api.mcp_server` | MCP tools over streamable HTTP (official SDK), authorized and audited per call |
| API | `api.a2a` | Agent Card, JSON-RPC `message/send` and `tasks/get` |
| Application | `application.service` | Use cases: targets, runs, gate, approvals, history, comparison, judge calibration; audit every state change |
| Application | `application.executor` | Bounded-concurrency probe execution, timeouts, retries, consecutive-error breaker, trace merge |
| Application | `application.scheduler` | Background runs with a cap on concurrent runs |
| Domain | `domain.models`, `domain.suites`, `domain.expansion` | Scenario schema, versioned suites, deterministic expansion, safe templating |
| Domain | `domain.statistics` | Wilson, cluster bootstrap, Newcombe, sample sizes, Cohen's kappa |
| Judges | `judges.markers`, `judges.tools`, `judges.llm`, `judges.panel` | Marker disclosure, forbidden tools, policy violations, approval bypass, LLM rubric with calibration |
| Adapters | `adapters.http`, `adapters.mcp`, `adapters.a2a`, `adapters.traces`, `adapters.reference` | Target wire contracts, independent traces, calibration targets |
| Scoring | `scoring.scorer`, `scoring.regression` | Per-category statistics, version regression |
| Gate | `gate.policy`, `gate.evaluator`, `gate.report` | Thresholds, PolicyEngine decision, Ed25519-signed reports |
| Security | `security.auth`, `security.access`, `security.egress`, `security.jwks` | OIDC verification, role and fabric authorization, SSRF egress guard |
| Integrations | `integrations.identity_fabric` | `/v1/authorize`, `/oauth2/introspect`, jwt-bearer credentials |
| Infrastructure | `infrastructure.database` | SQLAlchemy Core repositories (PostgreSQL in production, SQLite in tests) |
| Runtime | `runtime.container` | Composition root built from settings |

## Sequences

### Release gate from a pipeline

```mermaid
sequenceDiagram
  participant P as CI pipeline (action.yml)
  participant G as Platform
  participant T as Agent under test
  participant A as Audit chain
  P->>G: POST /v1/runs (GitHub OIDC token)
  G->>G: verify issuer, subject pattern, role release-pipeline
  G->>A: run.create (suite digest, seed)
  G-->>P: 202 queued
  loop each probe (bounded concurrency)
    G->>T: invocation (task + context, no category, no marker list)
    T-->>G: output, tool calls, status
    G->>G: merge external trace, run judges
  end
  G->>A: run.finish (counts)
  P->>G: GET /v1/runs/{id} until completed
  P->>G: POST /v1/runs/{id}/gate
  G->>G: Wilson upper bounds vs thresholds, regression vs last releasable version
  G->>G: PolicyEngine release-decision (deny-overrides, default deny)
  G->>G: sign canonical report (Ed25519)
  G->>A: gate.evaluate (report digest, matched rules, policy digests)
  G-->>P: pass | fail | require_approval + signed report
  P->>G: POST /v1/reports/verify
```

### Human approval

```mermaid
sequenceDiagram
  participant R as Release approver
  participant G as Platform
  participant A as Audit chain
  participant P as Pipeline (waiting)
  R->>G: GET /v1/gate/decisions/{id}/report
  R->>G: POST /approve {reason} (enterprise OIDC, role release-approver)
  G->>G: deny if approver == requester or approver is not a person
  G->>A: gate.approve (reason, report digest)
  G->>G: re-sign report with approval
  P->>G: GET decision -> approved
```

## Deployment view

```mermaid
flowchart TB
  subgraph region[GCP region]
    subgraph gke[GKE regional cluster]
      p1[crt-0 zone a]
      p2[crt-1 zone b]
    end
    lb[Internal ingress] --> p1 & p2
    p1 & p2 --> sql[(Cloud SQL PostgreSQL 16<br/>regional HA, CMEK)]
    p1 & p2 --> gcs[(GCS audit bucket<br/>retention policy, CMEK)]
    p1 & p2 -. workload identity .-> vertex[Vertex AI<br/>optional judge]
  end
  ci[GitHub Actions] -- OIDC --> lb
```

## Data

| Store | Data | Classification | Retention |
|---|---|---|---|
| PostgreSQL `targets` | Target registrations (no credentials; env var names only) | INTERNAL | Life of target |
| PostgreSQL `runs`, `probe_results` | Run metadata, statistics, per-probe verdicts, 1,000-char output excerpts and digests | CONFIDENTIAL | 2 years (release evidence) |
| PostgreSQL `gate_decisions` | Signed reports and approvals | CONFIDENTIAL | 7 years |
| Audit chains | Who did what, under which policy digest | CONFIDENTIAL | 7 years, retention-locked |
| Audit signing key | Ed25519 private key | SECRET | Rotated every 90 days |

Planted markers are synthetic values generated per probe; they are not
secrets and carry no meaning outside the run.
