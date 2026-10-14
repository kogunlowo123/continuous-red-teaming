# Observability

## Metrics (`/metrics`, own registry)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `crt_http_request_duration_seconds` | histogram | method, route, status | API latency and error rate (SLIs) |
| `crt_probes_total` | counter | category, outcome | Probes executed (pass, fail, error) |
| `crt_probe_duration_seconds` | histogram | target_kind | Target response time |
| `crt_runs_total` | counter | status | Runs finished |
| `crt_runs_active` | gauge | | Runs executing in this replica |
| `crt_gate_decisions_total` | counter | outcome | Release decisions |
| `crt_category_failure_rate_upper` | gauge | target, category | Wilson upper bound of the last gated run |
| `crt_access_denied_total` | counter | action | Refused requests |

Alert rules: `configs/prometheus/alerts.yaml` (error-budget burn, latency,
stuck runs, target errors, gate failure spikes, access denial spikes,
replicas down). Dashboard: `configs/grafana/continuous-red-teaming.json`.

## Traces

OpenTelemetry (agentic-core `configure_telemetry`, OTLP gRPC when
`CRT_OTLP_ENDPOINT` is set). FastAPI is instrumented (health and metrics
excluded); every probe is a `probe` span with `crt.scenario`, `crt.category`
and `crt.outcome`. LLM judge calls emit agentic-core GenAI metrics (tokens,
duration, cost, attempts).

## Logs

JSON logs via agentic-core structlog configuration with correlation IDs
(`X-Correlation-ID` accepted and echoed) and sensitive-key scrubbing. Target
outputs are never logged; per-probe evidence is stored as a 1,000-character
excerpt plus a SHA-256 digest of the full output.

## Audit

The signed hash chain is the system of record for decisions. Verify a chain
offline:

```python
from agentic_core.audit import AuditEvent, verify_chain
events = [AuditEvent.model_validate_json(line) for line in open("crt-0.jsonl")]
verify_chain(events, {"audit-2026-10": public_key})
```
