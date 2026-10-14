# Runbook: first deployment and startup

## Prerequisites

- GKE (or EKS/AKS) cluster >= 1.27 with External Secrets Operator and a
  `ClusterSecretStore` named `platform-secrets` bound to the cloud secret
  manager.
- An enterprise IdP application exposing roles `redteam-operator`,
  `redteam-auditor`, `release-approver` (and `release-pipeline` if a
  non-GitHub CI uses it).
- Optional: agent-identity-fabric reachable from the namespace.

## 1. Provision cloud resources

```bash
cd deployments/terraform/gcp        # or aws / azure
terraform init                      # configure an encrypted remote backend first
terraform apply -var-file=<environment>.tfvars
```

Record the outputs: GCP service account (workload identity), database URL
secret, audit bucket, KMS key.

## 2. Create the audit and report signing key

Never let Terraform generate it (state exposure). Generate an Ed25519 key on
an operator workstation and store it directly in the secret manager:

```bash
openssl genpkey -algorithm ed25519 \
  | gcloud secrets create continuous-red-teaming-audit-key-2026-10 --data-file=-
```

AWS: `aws secretsmanager create-secret --name continuous-red-teaming-audit-key-2026-10 --kms-key-id <kms_key_arn> --secret-string file:///dev/stdin`.
Azure: `az keyvault secret set --vault-name <vault> --name continuous-red-teaming-audit-key-2026-10 --file /dev/stdin`.

## 3. Namespace and secret sync

```bash
kubectl apply -k deployments/kubernetes
kubectl -n agent-validation get externalsecret   # all READY=True
```

If targets use `env_bearer` auth, create a Secret whose keys are the
`auth_env` names and reference it as `secrets.targetTokens`.

## 4. Install the chart

Create `<environment>.yaml` with every value marked REQUIRED in
`values.yaml` (public URL, trusted issuers, target allow list, MCP allowed
hosts, `secrets.auditKeyFile: audit-2026-10.pem`) plus the workload-identity
annotation from Terraform:

```bash
helm upgrade --install crt oci://ghcr.io/kogunlowo123/charts/continuous-red-teaming \
  --version 0.1.0 -n agent-validation -f <environment>.yaml --wait
```

## 5. Verify

```bash
kubectl -n agent-validation rollout status statefulset/crt-continuous-red-teaming
kubectl -n agent-validation port-forward svc/crt-continuous-red-teaming 8080:80
curl -sf localhost:8080/readyz
curl -s localhost:8080/.well-known/report-signing-keys | jq '.keys[].kid'
curl -s localhost:8080/.well-known/agent-card.json | jq '.skills[].id'
```

Expected: `{"status":"ready"}`, the active kid, three skills. Then run the
calibration check: register a `reference` target in staging (with
`allowReferenceTargets: true`), run `agent-baseline` and confirm the gate
passes for an all-zero profile and fails for a profile with
`marker_leak_rate: 0.2`.
