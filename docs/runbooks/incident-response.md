# Runbook: incident response

Severity follows the alert label: `page` is immediate, `ticket` is next
business day. Every action below is recorded in the audit chain; never edit
audit files or database rows by hand.

## Elevated 5xx

1. `kubectl -n agent-validation logs statefulset/crt-continuous-red-teaming --since=15m`;
   filter by `correlation_id` from failing requests.
2. `/readyz` returns 503 when PostgreSQL is unreachable: check Cloud SQL
   status and the database URL secret.
3. 503 `temporarily_unavailable` on agent requests means the identity fabric
   is down; the platform is failing closed by design. Pipelines using OIDC are
   unaffected.

## Target errors

Probes erroring at more than `max_error_rate` make categories
`insufficient_evidence` and the gate fails. That is correct behaviour.
Contact the target's owner (registration `owner`), check the target's
endpoint, credentials (`auth_env` variable present) and allow list.

## Gate failure spike

1. Compare the latest decisions' `gate_policy.digest`, `decision_policy.digest`
   and `suite_digest` with the previous day's: a policy or suite change
   explains a step change.
2. If a recent policy change is wrong, revert it in Git and redeploy; decisions
   already issued stay as they are (they were correct for the policy in force).

## Access denied spike

1. Query the audit chain for `access.denied` events: actor, requested action,
   reason.
2. Repeated denials for one subject indicate a misconfigured pipeline or a
   misused credential. Revoke the credential at the IdP or suspend the agent in
   the identity fabric.

## Suspected report forgery

1. `POST /v1/reports/verify` with the report in question. `valid: false`
   means content, digest or signature does not match.
2. Find the `gate.evaluate` audit event for the decision id; its
   `report_digest` is authoritative.
3. If the signing key may be exposed, follow `key-rotation.md` (emergency).

## Replicas down

Fewer than two replicas scraped: check node pool health, PDB, and recent
rollouts. In-flight runs on lost replicas are aborted on restart.
