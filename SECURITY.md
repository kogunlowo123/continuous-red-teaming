# Security Policy

## Supported versions

Security fixes are released for the latest minor version.

## Reporting a vulnerability

Do not open a public issue. Use GitHub private vulnerability reporting
(Security tab, "Report a vulnerability"). Include affected version, a
description of the issue, reproduction steps and impact.

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| Triage and severity (CVSS v4) | 10 business days |
| Fix for critical/high | 30 days from triage |
| Coordinated disclosure | After a fixed release is available |

## Scope

In scope: code in this repository, including authentication and
authorization, the egress guard, judges, the release gate, report signing and
the composite GitHub Action.

Out of scope: the behaviour of agents under test (report those to their
owners), and requests to add realistic attack content to suites (see
ADR-0001).
