# Runbook: disaster recovery

| Component | RPO | RTO | Mechanism |
|---|---|---|---|
| PostgreSQL | 5 minutes | 1 hour | Regional HA, PITR, 14 daily backups |
| Audit chains | Shipper interval | n/a (append-only) | Per-replica volume shipped to retention-locked bucket |
| Signing key | 0 | 15 minutes | Secret manager replication |
| Platform | 0 | 15 minutes | Stateless image and chart from GHCR |

## Region loss (GCP)

1. Restore Cloud SQL from the latest backup or PITR into the recovery region
   (`gcloud sql instances clone` / restore) and update the database URL
   secret.
2. Apply `deployments/terraform/gcp` in the recovery region (new KMS key ring,
   bucket name suffix as required) and install the chart with the same audit
   key secret.
3. Runs that were executing are aborted on startup; pipelines retry.
4. Verify: `/readyz`, `GET /v1/gate/decisions?limit=5` returns recent
   decisions, `POST /v1/reports/verify` on one of them returns valid.

## Audit volume loss

A lost per-replica volume loses only events not yet shipped. Decisions are
still in PostgreSQL with their signed reports and audit sequence/hash; record
the gap in the incident log. New events start a fresh chain on the new
volume.
