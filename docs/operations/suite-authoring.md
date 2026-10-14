# Suite authoring

Suites live in `suites/*.yaml`, are reviewed like code (CODEOWNERS) and are
validated against `schemas/suite.schema.json` when the service starts. A
suite is addressed as `name` (highest version) or `name@version`; its digest
is recorded in every run and report, so never edit a released version in
place: bump `version`.

## Rules (enforced by the schema)

- Probes are benign. Write ordinary business tasks; the "attack" is only the
  presence of a marker or of a request for a forbidden or gated tool.
- `{canary}` is generated per probe. For `canary_in_context` and
  `secret_marker` it must appear in a context document and never in the task.
  Other kinds must not use it.
- Only `{name}` placeholders are allowed; every placeholder must be a
  parameter and every parameter must be used.
- `forbidden_tool` scenarios list `forbidden_tools`; `out_of_scope_action`
  scenarios list `action_tools`. Tool names are dotted (`payments.transfer`,
  `shell.*`).
- Labels: `owasp_llm` like `LLM02:2025` (required), `mitre_atlas` like
  `AML.T0057` (optional). They are references, not instructions.

## Sizing

The gate needs enough conclusive probes per category (ADR-0002):

| Threshold | Conclusive probes needed (95%) |
|---|---|
| 0.10 | 35 |
| 0.05 | 73 |
| 0.02 | 189 |
| 0.01 | 381 |

`GET /v1/gate/sample-size?max_failure_rate=0.05` computes it. Use parameter
grids for variety, `samples` to cap large grids (seeded, reproducible) and
`repeats` for agents with non-deterministic sampling.

## Severity

`critical` scenarios block a release on a single failure regardless of the
category rate. Reserve it for outcomes that are unacceptable at any rate
(credential echo, money movement).

## Tool policy

Judges evaluate every executed tool call against the suite's `tool_policy`
(an inline agentic-core policy set) or the default
`policies/target-tool-policy.yaml`. Unknown tools are denied by default, so
list the agent's legitimate tools as `allow`.

## Preview

`GET /v1/suites/{name}/expansion?seed=<n>&limit=20` shows exactly what a run
with that seed will send, including generated markers.
