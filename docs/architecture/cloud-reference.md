# Cloud reference implementation, cost and scalability

## Primary cloud: Google Cloud

| Concern | GCP service | Terraform (`deployments/terraform/gcp`) |
|---|---|---|
| Compute | GKE regional cluster (existing), StatefulSet from the Helm chart | Workload Identity binding `iam.gke.io/gcp-service-account` |
| Database | Cloud SQL for PostgreSQL 16, regional HA, private IP only, TLS required, PITR, 14 backups | `google_sql_database_instance.platform` |
| Encryption | Cloud KMS key ring and key (90-day rotation) as CMEK for Cloud SQL and the audit bucket | `google_kms_crypto_key.platform` |
| Secrets | Secret Manager (database URL); audit signing key created by operators | `google_secret_manager_secret.database_url` |
| Evidence | GCS bucket with retention policy (7 years, lockable), versioning, uniform access, public access prevention | `google_storage_bucket.audit` |
| LLM judge | Vertex AI Gemini via workload identity (`roles/aiplatform.user`, opt-in) | `google_project_iam_member.vertex_judge` |

AWS (EKS, RDS PostgreSQL Multi-AZ, KMS, Secrets Manager, S3 Object Lock
compliance mode, IRSA) and Azure (AKS, PostgreSQL Flexible Server
zone-redundant, Key Vault premium with RBAC, immutable blob storage, Workload
Identity) are implemented in `deployments/terraform/aws` and `azure` with the
same outputs.

## Scalability

- **API tier** is stateless apart from in-flight runs and the per-replica
  audit file; HPA scales on CPU between 2 and 8 replicas.
- **Run execution** is bounded per replica by `CRT_MAX_ACTIVE_RUNS` (default
  4) and per run by `CRT_PROBE_CONCURRENCY` (default 8), so a slow target
  cannot exhaust the platform and the platform cannot overload a target.
- **Probe volume**: the baseline suite is 394 probes. At concurrency 8 and a
  target answering in 2 s a run takes about 100 s; the platform's own
  overhead per probe (judging, persistence) is measured in
  `tests/performance` at well under 5 ms.
- **Database**: one row per probe result; 394 rows per run. 50 releases a day
  across all agents is about 7 million rows a year, well within a single
  Cloud SQL instance; results older than the retention period can be
  partitioned or archived by `created_at`.

## Cost drivers

Costs depend on contracted cloud and model prices, which are configuration,
not constants. The drivers to size are:

| Driver | Scales with | Lever |
|---|---|---|
| Cloud SQL instance | Storage and concurrent connections | Tier (`db_tier`), result retention |
| GKE pods | Concurrent runs | `CRT_MAX_ACTIVE_RUNS`, HPA bounds |
| Target load | Probes per release x releases | Suite `samples`, `repeats` |
| LLM judge | Probes judged by `llm_rubric` x tokens | Opt-in per scenario; deterministic judges first |
| Evidence storage | Audit chain volume (small JSON lines) | Retention period |

The deterministic judges have no per-call cost; the LLM judge is the only
variable spend and is opt-in per scenario.
