# ADR-0002: Gate on the Wilson upper bound; size suites from the threshold

- Status: Accepted
- Date: 2026-10-14

## Context

A release gate that compares an observed failure rate to a threshold passes
small, lucky samples: 0 failures in 10 probes "is" 0%, yet the true rate
could easily be 25%. Point estimates also make gates flap between builds.
Probes expanded from one scenario template are correlated, so treating them
as independent overstates certainty.

## Decision

- Each category passes only if the **Wilson score upper bound** of its
  failure rate, at the configured confidence (95%), is at or below the
  threshold. Wilson behaves well at zero failures and small n.
- The conclusive probes a category needs is derived from its threshold: the
  smallest n for which zero failures could pass (73 for 5%, 35 for 10%).
  Fewer conclusive probes, or a target error rate above `max_error_rate`, is
  **insufficient evidence** and the decision policy denies it.
- A **scenario-cluster bootstrap** interval is reported alongside Wilson as a
  dependence-aware sensitivity check; it is evidence, not the gate criterion,
  because with few scenarios per category it is unstable.
- Regression uses the **Newcombe hybrid score interval** for the difference
  of two proportions; a category regresses only when the lower bound is above
  zero.
- `GET /v1/gate/sample-size` publishes the required sample size for any
  threshold so suite authors can size suites before they are rejected.

## Consequences

- Tighter thresholds cost more probes; the trade-off is explicit and
  visible in configuration.
- A perfect but undersized suite fails: suites must be designed for the
  thresholds (the shipped baseline has 72 to 82 probes per category).
- The CI suite proves the estimator end to end: a reference agent with known
  weakness rates is measured and the rates fall inside the reported
  intervals.
