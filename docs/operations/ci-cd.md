# CI/CD

## This repository

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Gates |
|---|---|
| `quality` (3.12, 3.13) | ruff, black, mypy `--strict`, bandit, contract drift, pytest (unit, security, chaos, performance, e2e incl. schemathesis) with >= 90% branch coverage, pip-audit |
| `integration-postgres` | Repositories and a full run plus gate on PostgreSQL 16 |
| `deploy-artifacts` | Helm lint and render, required-values check, kubeconform, Terraform fmt and validate for GCP, AWS and Azure, Trivy config scan |
| `container` | Image build, smoke test, then the composite action itself against the running image: a hardened reference agent must pass, a weak one must be blocked; Trivy image scan, Syft SBOM, Grype gate |
| `semgrep` | Python, secrets, Dockerfile and GitHub Actions rule packs |

`.github/workflows/release.yml` on a `v*.*.*` tag re-runs the quality gate,
checks the tag matches the package and chart versions, pushes the image to
GHCR with SBOM and provenance attestation, pushes the Helm chart to GHCR OCI,
and creates a GitHub release with the SBOM.

## Gating agent releases with the composite action

```yaml
jobs:
  release-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - id: gate
        uses: kogunlowo123/continuous-red-teaming@v0.1.0
        with:
          gate-url: ${{ vars.RED_TEAM_GATE_URL }}
          target-id: ${{ vars.AGENT_TARGET_ID }}
          target-version: ${{ github.sha }}
          suite: agent-baseline@2026.10.0
          environment: production
          approval-wait-minutes: "60"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: release-gate-report
          path: release-gate-report.json
  deploy:
    needs: release-gate
    # runs only when the gate step succeeded (pass or approved)
```

Platform configuration for GitHub OIDC (Helm `platform.trustedIssuers`):

```yaml
- issuer: https://token.actions.githubusercontent.com
  jwks_url: https://token.actions.githubusercontent.com/.well-known/jwks
  audience: continuous-red-teaming
  kind: pipeline
  default_roles: [release-pipeline]
  subject_patterns: ["repo:<org>/<agent-repo>:ref:refs/heads/main",
                     "repo:<org>/<agent-repo>:environment:production"]
```

Inputs, outputs and exit codes are documented in `action.yml` and ADR-0006.
