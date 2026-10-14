# Runbook: monitoring

Dashboard: `configs/grafana/continuous-red-teaming.json`. Alerts:
`configs/prometheus/alerts.yaml`.

| Signal | Normal | Investigate when |
|---|---|---|
| `crt:request_errors:ratio_5m` | < 0.1% | Fast-burn alert fires |
| p99 GET latency | < 250 ms | Above for 10 minutes |
| `crt_runs_active` | 0 to `maxActiveRuns` x replicas | Non-zero for 30 minutes with no runs finishing |
| `crt_probes_total{outcome="error"}` share | < 5% | Above 20% |
| `crt_gate_decisions_total{outcome="fail"}` | Matches release cadence | More than 5 per hour |
| `crt_access_denied_total` | Near zero | Sustained > 0.2/s |

## Latency

1. Check database health (Cloud SQL CPU, connections) and `/readyz`.
2. Check result page sizes: clients should page `/results` with `limit` <= 500.
3. Scale out (HPA max) if CPU-bound; runs are spread by replica.

## Stuck runs

1. `GET /v1/runs?status=running` to list them; check the target's health.
2. A target that answers slowly holds the run up to `timeout_s` per probe per
   attempt. Lower the target's `timeout_s` or fix the target.
3. Restarting the replica aborts its in-flight runs (recorded as
   "interrupted by restart"); pipelines start new runs.

## Measurement accuracy

Weekly in staging: run `agent-baseline` against reference targets with known
weakness rates and confirm each configured rate falls inside the reported
Wilson interval for its category. A miss means a judge or adapter regression;
stop gating new categories until resolved.
