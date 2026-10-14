# Continuous Red Teaming

Autonomous agent validation and release engineering. Every release of an AI
agent is run against versioned suites of benign synthetic probes, judged
deterministically, scored with confidence intervals per risk category,
compared with the last releasable version, and gated: the pipeline gets a
signed `pass`, `fail` or `require_approval`, and only a person can approve.

```
Scenario Suite ─▶ Probe Execution ─▶ Evaluation ─▶ Scoring ─▶ Release Gate
 (YAML, digest)   (HTTP / MCP / A2A)  (judges)     (Wilson,     (thresholds + policy,
                                                    bootstrap,   signed report,
                                                    Newcombe)    human approval)
```

## Why

Agents ship weekly; their prompts, models, tools and retrieval sources change
underneath them. A one-off red-team exercise says nothing about next week's
build. Release managers need a repeatable answer to one question per
release: is this version at least as safe as the last one, with evidence an
auditor can verify?

## Scope: benign probes only

Validation never uses realistic jailbreak, injection or exfiltration text. A
probe is a structured scenario that plants a marker the agent must not act on
or reveal:

| Probe kind | What is planted | Failure means |
|---|---|---|
| `canary_in_context` | `CANARY-<uuid>` inside a retrieved document | the marker appears in the output or a tool argument (any encoding) |
| `secret_marker` | a fake credential value `CANARY-<uuid>` in a config/notes record | the value is echoed |
| `forbidden_tool` | a request to use a tool on the scenario's forbidden list | the tool was executed |
| `out_of_scope_action` | a request for an action the tool policy gates behind approval | the action was executed without an approval reference |

Scenarios carry OWASP LLM Top 10 (2025) and MITRE ATLAS identifiers as labels
for traceability only.

## Capabilities

| Capability | Implementation |
|---|---|
| Versioned suites | YAML validated against `schemas/suite.schema.json`; content digest recorded in every run and report |
| Deterministic expansion | Sorted parameter grids, seeded sampling, HMAC-derived markers and session ids: same seed, same probes |
| Target adapters | HTTP agent endpoints, MCP servers (official `mcp` client, streamable HTTP), A2A `message/send` with task polling; independent trace endpoints merged into judging |
| Judges | Marker leakage (verbatim, case, separators, bare UUID, reversed, base64, hex), forbidden tool execution, tool-policy violations (agentic-core PolicyEngine, default deny), approval bypass; optional LLM rubric judge behind ContentGuard, advisory until calibrated (Cohen's kappa) |
| Statistics | Wilson score intervals, scenario-cluster bootstrap, Newcombe difference intervals, zero-failure sample sizes |
| Release gate | Per-category thresholds on the Wilson upper bound, insufficient-evidence detection, release decision through a versioned PolicyEngine policy, two-person approval |
| Evidence | Ed25519-signed evaluation reports (canonical JSON), hash-chained signed audit log (agentic-core), public keys at `/.well-known/report-signing-keys` |
| Regression tracking | Baseline = last releasable version; significant per-category regressions and scenario flips |
| Interfaces | REST, MCP tools at `/mcp/`, A2A Agent Card and JSON-RPC at `/a2a`, reusable composite GitHub Action (`action.yml`) |
| Identity | Enterprise OIDC and CI workload OIDC (GitHub Actions) for people and pipelines; agent credentials authorized by agent-identity-fabric |
| Calibration targets | In-process reference agents with known weakness rates prove the platform measures what it claims |

## Use it in a pipeline

```yaml
permissions:
  contents: read
  id-token: write          # the action authenticates with the job's OIDC token
steps:
  - uses: kogunlowo123/continuous-red-teaming@v0.1.0
    with:
      gate-url: ${{ vars.RED_TEAM_GATE_URL }}
      target-id: ${{ vars.SUPPORT_AGENT_TARGET_ID }}
      target-version: ${{ github.sha }}
      suite: agent-baseline@2026.10.0
      environment: production
      approval-wait-minutes: "60"
```

The step fails unless the gate returns `pass` (or a person approves a
`require_approval` decision while it waits). It writes a job summary table,
the signed report file, and the outputs `outcome`, `decision-id`, `run-id`,
`report-digest`. See [CI/CD](docs/operations/ci-cd.md).

## Quick start (local)

No API keys or cloud credentials are needed.

```bash
uv sync
make check                 # ruff, black, mypy --strict, bandit, contracts, tests (coverage >= 90%)
docker compose up --build  # platform, PostgreSQL, OIDC provider, reference agent, OTel collector
```

## API

| Endpoint | Caller | Purpose |
|---|---|---|
| `GET /v1/suites`, `/v1/suites/{ref}`, `/v1/suites/{ref}/expansion` | any platform role | Suites and deterministic probe preview |
| `POST /v1/targets`, `GET /v1/targets[/{id}]` | operator / readers | Register agents under test |
| `POST /v1/runs`, `GET /v1/runs[/{id}]`, `GET /v1/runs/{id}/results` | operator, pipeline / readers | Validation runs and per-probe evidence |
| `POST /v1/runs/{id}/gate` | operator, pipeline | Release gate decision with signed report |
| `GET /v1/gate/decisions[/{id}][/report]` | readers | Decisions and signed reports |
| `POST /v1/gate/decisions/{id}/approve` | release approver (not the requester) | Human sign-off |
| `POST /v1/reports/verify`, `GET /.well-known/report-signing-keys` | readers / anyone | Report verification |
| `GET /v1/targets/{id}/history`, `/comparison` | readers | Regression tracking |
| `GET /v1/gate/sample-size` | readers | Probes needed for a threshold |
| `/mcp/` | agents and people | MCP tools: `list_suites`, `start_validation_run`, `get_run`, `evaluate_release_gate`, `compare_versions` |
| `/.well-known/agent-card.json`, `POST /a2a` | agents | A2A skills: `start-validation-run`, `evaluate-release-gate`, `compare-versions` |

Full contract: [docs/api/openapi.json](docs/api/openapi.json); JSON Schemas in [schemas/](schemas/).

## Deployment

| Layer | Location |
|---|---|
| Container image | `Dockerfile` (non-root uid 10001, read-only root filesystem compatible) |
| Helm chart | `deployments/helm/continuous-red-teaming` (StatefulSet with per-replica audit volume, PDB, HPA, NetworkPolicy, ServiceMonitor) |
| Namespace and secret sync | `deployments/kubernetes` (restricted Pod Security, External Secrets) |
| Cloud infrastructure | `deployments/terraform/{gcp,aws,azure}`; GCP is the reference deployment |

## Documentation

- [Architecture](docs/architecture/overview.md), [agent specification](docs/architecture/agent-specification.md), [integrations (MCP, A2A, identity)](docs/architecture/integrations.md), [cloud reference, cost and scale](docs/architecture/cloud-reference.md), [acceptance criteria](docs/architecture/acceptance-criteria.md)
- [ADRs](docs/architecture/adr/)
- [Threat model](docs/security/threat-model.md), [compliance mapping](docs/compliance/control-mapping.md)
- [Suite authoring](docs/operations/suite-authoring.md), [configuration](docs/operations/configuration.md), [observability](docs/operations/observability.md), [CI/CD](docs/operations/ci-cd.md)
- Runbooks: [startup](docs/runbooks/startup.md), [monitoring](docs/runbooks/monitoring.md), [incident response](docs/runbooks/incident-response.md), [release approval](docs/runbooks/release-approval.md), [key rotation](docs/runbooks/key-rotation.md), [rollback](docs/runbooks/rollback.md), [disaster recovery](docs/runbooks/disaster-recovery.md)

Shared controls (policy engine, audit chain, model routing, content guard,
logging, telemetry) come from [agentic-core](https://github.com/kogunlowo123/agentic-core);
agent identity from [agent-identity-fabric](https://github.com/kogunlowo123/agent-identity-fabric).

## License

Apache-2.0
