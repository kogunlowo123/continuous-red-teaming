# ADR-0005: Per-replica audit chains and run ownership (StatefulSet)

- Status: Accepted
- Date: 2026-10-14

## Context

A hash chain has one writer. Several replicas appending to one file would
interleave sequences and break verification; a shared database table would
need a global lock on every audit write. Runs execute as background tasks in
the replica that accepted them; a replica restart loses its in-memory tasks.

## Decision

- Each replica writes its own signed chain to a persistent volume
  (`/var/lib/continuous-red-teaming/audit/<pod>.jsonl`) that a log shipper
  copies to the retention-locked bucket. The chart is therefore a
  StatefulSet with a volume claim template, as in agent-identity-fabric.
- Runs left `queued` or `running` when a replica starts are marked
  `aborted` with reason "interrupted by restart" and audited; callers start
  a new run. Results are never partially reused across processes.
- The scheduler caps concurrent runs per replica and returns 429 with
  `Retry-After` when full.

## Consequences

- Chains verify independently per replica with `agentic_core.audit.verify_chain`.
- A rolling update aborts in-flight runs; pipelines retry. Typical runs take
  minutes, and the CI action treats an aborted run as an operational error
  (exit code 2), distinct from a gate failure (exit code 1).
