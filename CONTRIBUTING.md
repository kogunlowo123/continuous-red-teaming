# Contributing

## Setup

```bash
uv sync
make check
```

## Requirements for every change

- `make check` passes: ruff, black, mypy `--strict`, bandit, contract drift,
  tests with at least 90% branch coverage.
- New behaviour has tests. Security controls need adversarial cases in
  `tests/security`; failure handling needs cases in `tests/chaos`.
- Probes stay benign (ADR-0001): markers, forbidden-tool and gated-action
  requests only. Pull requests adding realistic attack text are declined.
- Changing a released suite means a new suite `version`; never edit a
  released version in place.
- Public API or schema changes regenerate contracts
  (`uv run python -m continuous_red_teaming.contracts`) and are recorded in
  `CHANGELOG.md`.
- Architecturally significant decisions get an ADR in `docs/architecture/adr/`.
- No credentials, customer data or PHI in code, tests or fixtures.

## Commit messages

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`). Breaking changes use `!` and a `BREAKING CHANGE:` footer.

## Review

Changes to `policies/`, `suites/`, `src/continuous_red_teaming/{security,gate,judges}`,
`deployments/` or `action.yml` need approval from the code owners
(see `CODEOWNERS`).
