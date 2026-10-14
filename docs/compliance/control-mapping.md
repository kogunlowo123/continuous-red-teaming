# Compliance control mapping

Evidence column names the artifact an auditor can inspect.

| Control objective | SOC 2 (TSC 2017) | ISO/IEC 27001:2022 | NIST SP 800-53 r5 | NIST AI RMF 1.0 | HIPAA Security Rule | 21 CFR Part 11 / GxP CSA | Evidence |
|---|---|---|---|---|---|---|---|
| AI system tested before release | CC8.1 | 8.29, 8.32 | SA-11, CA-2 | MEASURE 2.3, MEASURE 2.7 | 164.308(a)(8) | CSA risk-based testing; 11.10(a) | Signed evaluation report per release, `gate_decisions` |
| Test methods are documented and versioned | CC8.1 | 5.37, 8.32 | SA-11(1), CM-3 | MAP 2.3, MEASURE 1.1 | 164.316(b)(1) | 11.10(k) | Suites in Git with digest in each run, ADRs |
| Measurements are statistically sound | — | 9.1 | CA-7 | MEASURE 2.1, MEASURE 4.2 | — | CSA: fit-for-purpose assurance | Wilson/Newcombe intervals in reports, ADR-0002, reference-agent accuracy tests |
| Risk thresholds set by accountable owners | CC3.2 | 6.1.2 | RA-3, PM-9 | GOVERN 1.3, MANAGE 1.2 | 164.308(a)(1)(ii)(B) | Risk-based approach | `policies/release-gate.yaml`, `release-decision.yaml`, CODEOWNERS |
| Human oversight for high-risk releases | CC5.2 | 5.3 | AC-5, CM-3(2) | GOVERN 3.2, MANAGE 2.4 | 164.308(a)(3) | 11.10(g), 11.200 | `gate.approve` audit events, two-person rule tests |
| Regression monitoring across versions | CC7.1 | 8.16 | CA-7, SI-4 | MEASURE 3.1, MANAGE 4.1 | 164.308(a)(8) | Periodic review | Regression section of reports, `/history`, `/comparison` |
| Tamper-evident records | CC7.2 | 8.15 | AU-9, AU-10 | MEASURE 2.8 | 164.312(b), 164.312(c)(1) | 11.10(c), 11.10(e) | Signed hash chain in retention-locked storage, report signatures |
| Access control and least privilege | CC6.1, CC6.3 | 5.15, 8.2 | AC-3, AC-6 | GOVERN 2.1 | 164.312(a)(1) | 11.10(d), 11.10(g) | `policies/platform-access.yaml`, OIDC issuers, fabric scopes |
| Secure configuration and supply chain | CC7.1 | 8.9, 8.28 | CM-6, SR-3 | MANAGE 3.1 | 164.308(a)(1) | CSA: vendor assessment | CI: Trivy, Grype, Semgrep, pip-audit, SBOM, provenance attestation |
| Monitoring and incident response | CC7.3 | 5.24 | IR-4, SI-4 | MANAGE 4.3 | 164.308(a)(6) | — | Alert rules, incident runbook |
| Availability and recovery | A1.2 | 8.13, 8.14 | CP-9, CP-10 | — | 164.308(a)(7) | — | HA database, PITR, DR runbook |

HITRUST: the HIPAA, ISO 27001 and NIST 800-53 rows map to HITRUST CSF
domains 06 (Configuration Management), 09 (Transmission/Audit Logging), 10
(Information Systems Acquisition, Development and Maintenance) for
organisations that certify against it.

GxP: for agents used in regulated processes, the signed report for a release
is test evidence under a risk-based Computer Software Assurance approach;
the platform's own CI run for its release tag is the operational
qualification evidence for the functions listed in
`docs/architecture/acceptance-criteria.md`.
