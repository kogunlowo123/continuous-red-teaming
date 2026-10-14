# ADR-0003: Release decisions through the PolicyEngine; reports signed with the audit key

- Status: Accepted
- Date: 2026-10-14

## Context

Statistics say whether each category met its threshold; whether a release
may proceed also depends on risk tier, environment, regressions and
advisory findings. Hard-coding that logic hides it from governance review.
And a gate result that is only a log line cannot be shown to an auditor
months later.

## Decision

- The statistical assessment produces integer facts (breached categories,
  insufficient categories, critical failures, regressions, advisory
  findings, target risk, categories assessed). The decision is made by the
  agentic-core PolicyEngine over `policies/release-decision.yaml`:
  deny-overrides, then require_approval, then allow, default deny.
- The evaluation report (target, version, suite digest, seed, statistics,
  assessments, regression, matched rules, both policies' digests, LLM judge
  state, outcome, approvals) is serialized as canonical JSON, hashed with
  SHA-256 and signed with Ed25519 using the same key as the audit chain.
- The gate decision is recorded in the hash-chained audit log with the
  report digest before the API returns it. If the audit write fails, the
  decision fails.
- Approvals re-sign the report with the approval included and are recorded
  as their own audit events.
- Public keys (current and retired) are published at
  `/.well-known/report-signing-keys` as an OKP JWKS.

## Consequences

- Changing who may release under which conditions is a reviewed YAML change,
  and every report proves which policy version produced it.
- Reports verify offline; the audit chain proves ordering and time.
- One key signs both audit events and reports; its rotation is covered by
  `docs/runbooks/key-rotation.md` and retired keys stay verifiable.
