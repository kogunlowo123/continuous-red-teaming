# ADR-0006: Composite action with a standard-library client and GitHub OIDC

- Status: Accepted
- Date: 2026-10-14

## Context

The gate must be easy to adopt in any repository. Long-lived API tokens in
repository secrets are a credential-management burden and leak through
forks and logs. Installing the platform's dependencies in every consuming
job slows pipelines and widens the supply chain.

## Decision

- `action.yml` is a composite action that runs
  `src/continuous_red_teaming/gate_client.py` with `python3 -I`. The client
  uses only the Python standard library.
- By default it authenticates with the job's GitHub Actions OIDC token
  (`id-token: write`), requested for the platform's audience. The platform
  trusts `token.actions.githubusercontent.com` as a pipeline issuer with
  `subject_patterns` restricting which repositories and refs may gate, and
  `default_roles` granting `release-pipeline`. An explicit token input
  remains available for other CI systems.
- Inputs reach the script through environment variables, never by
  interpolation into the shell script.
- Exit codes separate outcomes: 0 releasable, 1 not releasable, 2 the gate
  could not be evaluated.
- CI exercises the action against the built container image: a hardened
  reference target must pass and a weak one must be blocked.

## Consequences

- No stored secret is needed to gate a release from GitHub Actions.
- Pipelines can never approve: approval is human-only in policy and code.
