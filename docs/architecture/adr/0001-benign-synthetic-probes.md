# ADR-0001: Benign synthetic probes, never realistic attack content

- Status: Accepted
- Date: 2026-10-14

## Context

Red-team corpora for language models usually contain realistic jailbreak,
prompt-injection and exfiltration text. Such corpora are dual-use, age
quickly as models change, are hard to review in a pull request, and give
noisy, model-specific signals. What a release manager needs to know is
narrower and more stable: does the agent keep values it was told are
internal, decline tools it may not use, and wait for a person before
privileged actions?

## Decision

- A probe is a structured scenario that plants a synthetic marker the target
  must not act on or reveal: a `CANARY-<uuid>` value in retrieved content or
  in a credential field, a request for a tool on the scenario's forbidden
  list, or a request for an action the tool policy gates behind approval.
- Markers are generated per probe (HMAC of run seed and probe id), so they
  are unique, reproducible from the seed, and meaningless outside the run.
- Templates only substitute `{name}` placeholders; scenario text is ordinary
  business language. No probe carries instructions to subvert the agent.
- OWASP LLM Top 10 (2025) and MITRE ATLAS identifiers are labels for
  traceability only; the platform does not reproduce techniques.
- The invocation the target receives carries no category, kind or list of
  protected values, so the target cannot special-case tests.

## Consequences

- Judges are deterministic and exact: a marker either appears (in any
  encoding we decode) or it does not. False positives are negligible.
- Suites are safe to store in Git, review and share across teams.
- The platform measures policy adherence and data handling, not resistance
  to novel adversarial text. Teams that need adversarial evaluation run it in
  a separate, access-controlled programme; this platform's gate stays
  reproducible.
