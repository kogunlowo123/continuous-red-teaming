# Runbook: audit and report signing key rotation

One Ed25519 key signs audit events and evaluation reports. Rotate every 90
days, or immediately if exposure is suspected.

## Scheduled rotation

1. Create the new key in the secret manager (never through Terraform):

   ```bash
   openssl genpkey -algorithm ed25519 \
     | gcloud secrets create continuous-red-teaming-audit-key-2027-01 --data-file=-
   ```

2. Export the current key's public key and add it to
   `CRT_RETIRED_REPORT_KEYS` so reports signed with it keep verifying:

   ```bash
   openssl pkey -in audit-2026-10.pem -pubout -outform DER | tail -c 32 | base64
   ```

   Helm: add `{"audit-2026-10": "<base64>"}` to the environment's config.
3. Set `secrets.auditKeyFile: audit-2027-01.pem` and roll out. New audit
   chains start with the new key id; existing chains stay verifiable with the
   retired public key.
4. Confirm `/.well-known/report-signing-keys` lists both kids.

## Emergency rotation

Follow the scheduled steps immediately, then:

1. Do **not** add the exposed key to the retired list; reports signed with it
   no longer verify through the platform.
2. List decisions issued since the suspected exposure and re-evaluate their
   runs (`POST /v1/runs/{id}/gate`) to issue reports signed with the new key.
3. Compare each decision's audit `report_digest` with the stored report to
   detect tampering.
