# Configuration reference

All settings are `CRT_*` environment variables (see
`src/continuous_red_teaming/config.py`). The service refuses to start with
incomplete or unsafe configuration. List and object values are JSON.

| Variable | Required | Default | Description |
|---|---|---|---|
| `CRT_ENVIRONMENT` | no | `production` | `production` forbids ephemeral keys and plain-HTTP targets |
| `CRT_PUBLIC_URL` | yes | | Public base URL; advertised in the A2A agent card |
| `CRT_DATABASE_URL` | yes | | SQLAlchemy async URL (`postgresql+asyncpg://...`) |
| `CRT_AUDIT_KEY_FILE` | yes* | | Ed25519 PEM that signs audit events and reports; file stem is the key id |
| `CRT_DEV_EPHEMERAL_KEYS` | no | `false` | In-memory key, non-production only (replaces `CRT_AUDIT_KEY_FILE`) |
| `CRT_AUDIT_LOG_PATH` | no | `/var/lib/continuous-red-teaming/audit/audit.jsonl` | Audit chain file (per replica) |
| `CRT_RETIRED_REPORT_KEYS` | no | `{}` | `{"kid": "<base64 raw public key>"}` of retired signing keys |
| `CRT_TRUSTED_ISSUERS` | yes** | `[]` | OIDC issuers: `issuer`, `jwks_url`, `audience`, `kind` (`user`/`pipeline`), `roles_claim`, `default_roles`, `subject_patterns` |
| `CRT_FABRIC_URL` | no | | agent-identity-fabric base URL; enables agent callers |
| `CRT_FABRIC_ISSUER` | with fabric | | `iss` of fabric credentials |
| `CRT_FABRIC_CLIENT_ID` | no | | Platform agent id for the jwt-bearer grant (targets with `auth: fabric`) |
| `CRT_FABRIC_WORKLOAD_TOKEN_FILE` | with client id | | Projected service-account token path |
| `CRT_FABRIC_SCOPE` | no | | Scope requested for the platform credential |
| `CRT_TARGET_ALLOWED_HOSTS` | yes for network targets | `[]` | Host globs target and trace endpoints may use |
| `CRT_ALLOW_INSECURE_TARGETS` | no | `false` | Allow `http://` targets (refused in production) |
| `CRT_ALLOW_REFERENCE_TARGETS` | no | `false` | Allow in-process calibration targets |
| `CRT_SUITES_DIR` | no | `suites` | Directory of suite YAML files |
| `CRT_GATE_POLICY_FILE` | no | `policies/release-gate.yaml` | Statistical thresholds |
| `CRT_DECISION_POLICY_FILE` | no | `policies/release-decision.yaml` | Release decision rules |
| `CRT_ACCESS_POLICY_FILE` | no | `policies/platform-access.yaml` | Role rules for people and pipelines |
| `CRT_TARGET_TOOL_POLICY_FILE` | no | `policies/target-tool-policy.yaml` | Default tool rules judged against targets |
| `CRT_MAX_PROBES_PER_RUN` | no | `5000` | Refuse suites larger than this |
| `CRT_PROBE_CONCURRENCY` | no | `8` | Concurrent probes per run |
| `CRT_MAX_ACTIVE_RUNS` | no | `4` | Concurrent runs per replica (429 beyond) |
| `CRT_ABORT_AFTER_CONSECUTIVE_ERRORS` | no | `20` | Stop sending probes to a failing target |
| `CRT_PROVIDERS_FILE` | no | | agentic-core providers file; enables the LLM rubric judge |
| `CRT_LLM_JUDGE_CLASSIFICATION` | no | `2` (CONFIDENTIAL) | Classification of judge requests |
| `CRT_MCP_ALLOWED_HOSTS` | no | `["127.0.0.1:*","localhost:*"]` | Host headers accepted on `/mcp/` |
| `CRT_LOG_LEVEL` | no | `INFO` | |
| `CRT_OTLP_ENDPOINT` | no | | OTLP gRPC endpoint for traces |
| `CRT_HOST` / `CRT_PORT` | no | `127.0.0.1` / `8080` | Container image sets host `0.0.0.0` |
| `CRT_FORWARDED_ALLOW_IPS` | no | `127.0.0.1` | Proxies trusted for `X-Forwarded-*` |

\* unless `CRT_DEV_EPHEMERAL_KEYS=true`. \** at least one of
`CRT_TRUSTED_ISSUERS` or `CRT_FABRIC_URL`.

## LLM judge provider variables

`configs/providers.yaml` references: `GCP_REGION`, `GCP_PROJECT_ID`,
`GCP_ACCESS_TOKEN`, `GEMINI_INPUT_USD_PER_MTOK`, `GEMINI_OUTPUT_USD_PER_MTOK`,
`ANTHROPIC_API_KEY`, `CLAUDE_INPUT_USD_PER_MTOK`, `CLAUDE_OUTPUT_USD_PER_MTOK`.
Loading fails if any is unset.

## Target tokens

Targets with `auth: env_bearer` name an environment variable (`auth_env`)
holding their bearer token; the value is read at call time and never stored.
