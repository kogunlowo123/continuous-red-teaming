# Runbook: approving a gated release

A decision with outcome `require_approval` means every statistical check
passed but policy requires a person: a high or critical-risk agent going to
production (`approve-high-risk-production`), or advisory LLM-judge findings
(`approve-advisory-findings`).

1. Open the signed report: `GET /v1/gate/decisions/{id}/report`.
2. Verify it: `POST /v1/reports/verify` must return `valid: true`.
3. Review:
   - `assessments`: every category `pass`, with `upper_bound` and
     `conclusive` probes;
   - `regression`: baseline version and any scenario flips;
   - for advisory findings, `GET /v1/runs/{run_id}/results` and inspect the
     verdicts with `advisory: true`.
4. Approve with a reason that names the evidence you reviewed:

```bash
curl -X POST "$CRT_URL/v1/gate/decisions/$ID/approve" \
  -H "Authorization: Bearer $APPROVER_TOKEN" -H "Content-Type: application/json" \
  -d '{"reason": "Reviewed report <digest>; advisory finding is a false positive in scenario <id>"}'
```

The approver must hold `release-approver`, must be a person, and must not be
the principal that requested the decision. The report is re-signed with the
approval and a `gate.approve` audit event is recorded. A pipeline waiting with
`approval-wait-minutes` continues automatically.

Do not approve to work around a `fail`: failures are not approvable.
