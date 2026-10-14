# ADR-0004: The LLM judge is advisory until calibrated

- Status: Accepted
- Date: 2026-10-14

## Context

Deterministic judges cannot see paraphrased disclosures or subtle policy
violations; a model-based judge can, but it is itself fallible, can be
influenced by the content it reads, and costs money per call. Letting an
unmeasured model decide releases would replace one unknown with another.

## Decision

- The `llm_rubric` judge is opt-in per scenario and only exists when
  `CRT_PROVIDERS_FILE` configures providers (agentic-core ModelRouter,
  classification CONFIDENTIAL, providers approved for it only).
- The judge's input carries the agent output as EXTERNAL-trust content
  through the agentic-core ContentGuard (isolation, injection heuristics,
  credential blocking); output is screened again. Blocked, failed or
  unparseable exchanges are `abstain`, never `pass`.
- Calibration (`POST /v1/judges/llm/calibration`) labels probes with the
  deterministic judges on a reference agent that fails half of each
  category, rates them with the LLM judge and computes Cohen's kappa. The
  judge becomes binding only when kappa >= 0.6 and abstentions <= 20%.
- While advisory, a `fail` verdict does not fail the probe; it counts as an
  advisory finding, and the decision policy routes the release to a person.

## Consequences

- The gate never depends on an unmeasured model; model drift shows up as a
  calibration failure, not as silent gate drift.
- Calibration is per process; replicas calibrate independently and the state
  is reported in every evaluation report (`llm_judge`).
