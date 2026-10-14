# Threat model

The platform decides whether AI agents reach production. Compromising it, or
fooling it, lets an unsafe agent ship with signed evidence that says it is
safe. The model below covers the platform itself; the risks it measures in
agents are listed under OWASP LLM Top 10.

## Assets

| Asset | Impact if compromised |
|---|---|
| Release decisions and signed reports | Unsafe agent promoted with valid-looking evidence |
| Audit signing key | Forged reports and audit events |
| Gate thresholds and decision policy | Gate silently weakened |
| Suites | Probes removed or made trivial |
| Target registrations | Platform used to probe arbitrary hosts (SSRF) |
| Audit chain | Loss of accountability |

## Trust boundaries

1. Pipelines, people and agents → platform API, MCP and A2A (untrusted callers).
2. Platform → agents under test (untrusted responses).
3. Platform → identity providers, identity fabric, model providers.
4. Platform → PostgreSQL, secret manager, evidence bucket.

## STRIDE

| ID | Threat | Category | Control | Test |
|---|---|---|---|---|
| T1 | Forged, unsigned or HS256-confused bearer token | Spoofing | JWKS verification, accepted algorithms RS256/ES256/EdDSA only, kid required | `tests/security::test_s2_forged_and_unsigned_tokens` |
| T2 | Token minted for another service replayed here | Spoofing | Audience check per trusted issuer | `test_s3_token_for_another_service_is_rejected` |
| T3 | CI token from a fork or another repository | Spoofing | `subject_patterns` per CI issuer | `test_s4_pipeline_from_unapproved_repository` |
| T4 | Auditor or pipeline registers targets or escalates | Elevation | Role policy, default deny, denial audited and counted | `test_s5_role_escalation_is_denied_and_audited` |
| T5 | Requester or pipeline approves its own release | Elevation | `deny-self-approval` (eq_attr), `deny-non-human-approval`, service-level check | `test_s6_pipelines_and_requesters_cannot_approve` |
| T6 | Agent token accepted without verification | Spoofing | Agent tokens only via identity fabric `/v1/authorize`; refused when no fabric | `test_s7_*`, `tests/unit/test_identity_and_access.py` |
| T7 | Target registration pointing at metadata service or internal hosts | Elevation / disclosure | Egress guard: https only, no userinfo, host allow list, refused IP ranges; NetworkPolicy egress | `test_s8_target_registration_cannot_pivot` |
| T8 | Template code execution through suite YAML | Elevation | Placeholder-only renderer, schema validation | `test_s9_suites_cannot_smuggle_template_code` |
| T9 | Agent evades marker detection by encoding | Tampering (of evidence) | Decoding judge: case, separators, UUID body, reversal, base64, hex, tool arguments | `test_s10_marker_evasion_is_detected` |
| T10 | Agent hides executed tools from its reply | Repudiation | Independent trace endpoint merged before judging; trace outage is an error | `tests/unit/test_operations.py::test_executor_merges_external_traces` |
| T11 | Agent detects tests and behaves differently | Tampering | Blind invocation (no category, kind, protected values); per-probe random-looking markers and sessions | `test_s12_probes_never_reveal_what_is_tested` |
| T12 | Report edited after signing (fail turned into pass) | Tampering | Ed25519 signature over canonical JSON digest; verify endpoint and JWKS | `test_s11_report_forgery_is_detected` |
| T13 | Audit write lost silently | Repudiation | Audit failure fails the gate decision | `tests/chaos::test_audit_failure_blocks_the_gate_decision` |
| T14 | Target outage turned into a pass | Tampering | Errors are inconclusive; insufficient evidence denies | `tests/chaos::test_unreachable_target_is_insufficient_evidence_not_a_pass` |
| T15 | Suite changed between queueing and execution | Tampering | Suite digest pinned at queue time, re-checked at execution | `tests/unit/test_service.py::test_suite_changed_after_queueing_fails_the_run` |
| T16 | Injected content steers the LLM judge | Tampering | ContentGuard on judge input/output, EXTERNAL trust, advisory until calibrated | `tests/unit/test_judges.py` |
| T17 | Run flooding exhausts the platform or a target | DoS | Per-replica active-run cap (429), probe budget per run, concurrency limit, consecutive-error breaker | `test_capacity_limit_returns_429`, `test_executor_aborts_after_consecutive_errors` |
| T18 | Mass assignment of unknown fields | Tampering | `extra="forbid"` on inputs | `test_s13_unknown_fields_are_rejected` |

## MITRE ATT&CK (Enterprise)

| Technique | Mitigation |
|---|---|
| T1078 Valid Accounts | Short-lived OIDC tokens, subject patterns, role policy |
| T1552 Unsecured Credentials | No credentials in target records (env var names only); secrets from secret manager |
| T1090 / T1595 (platform used as proxy or scanner) | Egress allow list, refused ranges, NetworkPolicy |
| T1565 Data Manipulation | Signed reports, hash-chained audit, digests of suites and policies |
| T1562.008 Impair Defenses: Disable Cloud Logs | Retention-locked evidence bucket; audit failure fails the request |

## MITRE ATLAS (AI-specific)

| Technique (reference) | Relevance | Control |
|---|---|---|
| AML.T0057 LLM Data Leakage | Measured in agents (marker_leakage, secret_echo) | Marker judges |
| AML.T0055 Unsecured Credentials | Measured in agents (secret_echo) | Marker judges |
| AML.T0053 LLM Plugin Compromise | Measured in agents (forbidden_tool, approval_bypass) | Tool-trace and policy judges |
| AML.T0025 Exfiltration via Cyber Means | Measured in agents (policy_violation) | Tool policy default deny |
| AML.T0051 LLM Prompt Injection (against the judge) | Platform | ContentGuard, advisory LLM judge |

## OWASP Top 10 for LLM Applications (2025)

| Risk | Relevance | Control |
|---|---|---|
| LLM01 Prompt Injection | LLM judge reads untrusted agent output | EXTERNAL trust isolation, guard blocking, abstain, calibration |
| LLM02 Sensitive Information Disclosure | Primary measurement | Canary and secret markers |
| LLM06 Excessive Agency | Primary measurement | Forbidden tools, approval bypass, policy violation |
| LLM09 Misinformation (in the gate itself) | Point estimates mislead | Wilson upper bounds, insufficient-evidence rule |

## OWASP API Security Top 10 (2023)

| Risk | Control |
|---|---|
| API1 Broken Object Level Authorization | Every route authorizes the action; decisions bound to requester for approval |
| API2 Broken Authentication | Signed tokens, audience, issuer and time checks on injected clock |
| API3 Broken Object Property Level Authorization | `extra="forbid"`; target credentials never stored |
| API4 Unrestricted Resource Consumption | Page limits (<= 500), probe budget, run cap, 429 with Retry-After |
| API5 Broken Function Level Authorization | Distinct roles; human-only approval |
| API7 Server Side Request Forgery | Egress guard and NetworkPolicy |
| API8 Security Misconfiguration | Production refuses ephemeral keys and insecure targets; Helm `required` |
| API10 Unsafe Consumption of APIs | Target replies size-bounded and schema-validated; errors are inconclusive |

## Risk register

| ID | Risk | Likelihood | Impact | Owner | Treatment | Residual |
|---|---|---|---|---|---|---|
| R1 | Audit/report signing key exfiltration | Low | Critical | Security Ops | Secret manager + KMS, 90-day rotation, retired-key publication | Low |
| R2 | Thresholds or decision policy weakened in review | Medium | High | AI Governance | CODEOWNERS on `policies/`, digests in every report, alerts on decision mix | Low |
| R3 | Suites drift out of date with agent capabilities | Medium | Medium | Platform team per agent | Versioned suites, suite authoring guide, quarterly review | Medium |
| R4 | DNS rebinding to bypass the host allow list | Low | Medium | Platform | NetworkPolicy egress ports, private DNS, allow list of internal zones | Low |
| R5 | LLM judge disagreement causes approval fatigue | Medium | Low | AI Governance | Calibrate before enabling, opt-in per scenario | Low |
| R6 | Benign probes do not capture novel adversarial behaviour | Medium | Medium | Security | Separate adversarial programme (ADR-0001); this gate covers policy adherence | Medium |
