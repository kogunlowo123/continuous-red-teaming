# Acceptance criteria

Each criterion names the automated test that demonstrates it. The CI run for
a release tag is the operational-qualification evidence for that version.

| # | Criterion | Evidence |
|---|---|---|
| AC1 | The same suite and seed always expand to the same probes and markers; a different seed changes markers but not probe ids | `tests/unit/test_suites_and_expansion.py::test_expansion_is_deterministic_and_seed_sensitive` |
| AC2 | Suites with undefined placeholders, format specs, attribute access, markers in the task, invalid labels or oversize grids are rejected | `test_invalid_scenarios_are_rejected`, `tests/security::test_s9_*` |
| AC3 | Probes never reveal category, kind or protected values to the target | `tests/security::test_s12_probes_never_reveal_what_is_tested` |
| AC4 | A marker disclosed verbatim, case-altered, with separators, as the bare UUID, reversed, base64 or hex encoded, in output or tool arguments, fails the probe | `tests/unit/test_judges.py::test_marker_disclosure_forms`, `tests/security::test_s10_*` |
| AC5 | Executed forbidden tools, policy-denied tools and approval-gated actions without an approval reference fail the probe; proposed or blocked calls do not | `test_forbidden_tool_judge`, `test_policy_violation_judge_uses_default_deny`, `test_approval_bypass_judge` |
| AC6 | For reference agents with known weakness rates, every configured rate lies inside the measured Wilson interval (99.9%, across seeds and profiles) | `tests/unit/test_measurement_accuracy.py` |
| AC7 | HTTP, A2A and MCP adapters produce identical verdicts for the same agent | `tests/e2e/test_network_targets.py` |
| AC8 | A category passes only when its Wilson upper bound is within threshold with at least the zero-failure sample size of conclusive probes | `tests/unit/test_gate.py` |
| AC9 | Target outages produce insufficient evidence and `fail`, never `pass` | `tests/chaos::test_unreachable_target_is_insufficient_evidence_not_a_pass` |
| AC10 | A single failure in a critical scenario blocks release | `test_a_single_critical_failure_denies_even_within_threshold` |
| AC11 | A significant regression against the last releasable version blocks release | `test_regression_denies` |
| AC12 | High/critical-risk production releases require a person; the requester and pipelines cannot approve | `tests/e2e::test_production_release_needs_a_second_person`, `tests/security::test_s6_*` |
| AC13 | Reports are signed; any change to content, digest or signature fails verification | `test_report_tampering_is_detected`, `tests/security::test_s11_*` |
| AC14 | Every state change is in the signed audit chain; if the audit write fails the gate decision fails | `test_audit_chain_covers_every_state_change`, `tests/chaos::test_audit_failure_blocks_the_gate_decision` |
| AC15 | An uncalibrated LLM judge is advisory; its findings route the release to human approval | `test_uncalibrated_llm_findings_require_approval` |
| AC16 | Target registration cannot point at metadata, link-local or non-allow-listed hosts | `tests/security::test_s8_*` |
| AC17 | The composite GitHub Action exits 0 for a hardened agent and 1 for a weak one, and writes a signed report | `tests/e2e/test_gate_action_client.py`; container job in `.github/workflows/ci.yml` |
| AC18 | No generated API input causes a server error | `tests/e2e/test_api_contract.py` |
