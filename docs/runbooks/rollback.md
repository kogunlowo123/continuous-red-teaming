# Runbook: rollback

## Platform version

```bash
helm -n agent-validation history crt
helm -n agent-validation rollback crt <revision> --wait
```

The schema is additive (`schema_version` table); a previous version reads
newer rows because aggregates are stored as JSON documents validated on read.
In-flight runs on restarted replicas are aborted and must be restarted by
their pipelines.

## Policy or suite change

Thresholds, decision rules, tool rules and suites ship in the image. Revert
the commit, build and roll out. Decisions already issued remain valid for the
policy digest recorded in their reports; re-evaluate affected runs if needed.

## An agent release that passed but misbehaves in production

Rolling back the agent is the agent team's deployment action, not the
platform's. Use `/v1/targets/{id}/history` to find the last version whose
decision was `pass` or `approved` and its signed report as the rollback
target's evidence; then add a scenario covering the missed behaviour.
