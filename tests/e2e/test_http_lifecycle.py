"""The release-validation lifecycle over HTTP, as operators, pipelines and approvers use it."""

from __future__ import annotations

import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from continuous_red_teaming.domain.models import ReferenceProfile, Severity
from tests.conftest import (
    FakeClock,
    FakeIdp,
    pipeline_headers,
    reference_registration,
    user_headers,
)

pytestmark = pytest.mark.e2e


def register(
    client: TestClient,
    idp: FakeIdp,
    name: str = "support-agent",
    profile: ReferenceProfile | None = None,
    risk: Severity = Severity.MODERATE,
) -> str:
    body = reference_registration(name, profile or ReferenceProfile(), risk=risk)
    response = client.post(
        "/v1/targets",
        json=body.model_dump(mode="json"),
        headers=user_headers(idp, "redteam-operator"),
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def run_to_completion(
    client: TestClient, headers: dict[str, str], target_id: str, version: str, **extra: Any
) -> dict[str, Any]:
    started = client.post(
        "/v1/runs",
        json={
            "target_id": target_id,
            "target_version": version,
            "suite": "agent-baseline",
            **extra,
        },
        headers=headers,
    )
    assert started.status_code == 202, started.text
    assert started.json()["status"] == "queued"
    run_id = started.json()["id"]
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        run: dict[str, Any] = client.get(f"/v1/runs/{run_id}", headers=headers).json()
        if run["status"] in {"completed", "failed", "aborted"}:
            assert run["status"] == "completed", run
            return run
        time.sleep(0.05)
    raise AssertionError("run did not complete")


def test_pipeline_release_lifecycle(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp, clock: FakeClock
) -> None:
    pipeline = pipeline_headers(ci_idp)
    auditor = user_headers(enterprise_idp, "redteam-auditor")

    suites = client.get("/v1/suites", headers=pipeline).json()["items"]
    assert suites[0]["name"] == "agent-baseline"
    assert suites[0]["probe_count"] == 394
    suite = client.get("/v1/suites/agent-baseline@2026.10.0", headers=pipeline).json()
    assert {s["category"] for s in suite["scenarios"]} >= {"marker_leakage", "secret_echo"}
    preview = client.get(
        "/v1/suites/agent-baseline/expansion", params={"seed": 5, "limit": 3}, headers=pipeline
    ).json()
    assert preview["probe_count"] == 394
    assert len(preview["probes"]) == 3

    target_id = register(client, enterprise_idp)
    run = run_to_completion(client, pipeline, target_id, "1.0.0", seed=5)
    assert run["summary"]["failures"] == 0
    results = client.get(
        f"/v1/runs/{run['id']}/results", params={"limit": 10}, headers=auditor
    ).json()
    assert len(results["items"]) == 10

    gate = client.post(f"/v1/runs/{run['id']}/gate", headers=pipeline)
    assert gate.status_code == 201, gate.text
    decision = gate.json()
    assert decision["outcome"] == "pass"
    report = client.get(f"/v1/gate/decisions/{decision['id']}/report", headers=auditor).json()
    verified = client.post("/v1/reports/verify", json=report, headers=auditor).json()
    assert verified["valid"] is True
    report["report"]["outcome"] = "approved"
    assert client.post("/v1/reports/verify", json=report, headers=auditor).json()["valid"] is False
    keys = client.get("/.well-known/report-signing-keys").json()["keys"]
    assert keys[0]["kid"] == report["signature"]["key_id"]

    clock.advance(60)
    second = run_to_completion(client, pipeline, target_id, "1.1.0", seed=6)
    second_decision = client.post(f"/v1/runs/{second['id']}/gate", headers=pipeline).json()
    assert second_decision["signed_report"]["report"]["regression"]["baseline_version"] == "1.0.0"
    history = client.get(f"/v1/targets/{target_id}/history", headers=auditor).json()
    assert [p["target_version"] for p in history["points"]] == ["1.1.0", "1.0.0"]
    comparison = client.get(
        f"/v1/targets/{target_id}/comparison",
        params={"baseline": "1.0.0", "candidate": "1.1.0"},
        headers=auditor,
    ).json()
    assert comparison["baseline_version"] == "1.0.0"
    listed = client.get("/v1/gate/decisions", params={"target_id": target_id}, headers=auditor)
    assert len(listed.json()["items"]) == 2
    assert (
        len(
            client.get("/v1/runs", params={"target_id": target_id}, headers=auditor).json()["items"]
        )
        == 2
    )
    assert client.get(f"/v1/targets/{target_id}", headers=auditor).json()["name"] == "support-agent"
    assert len(client.get("/v1/targets", headers=auditor).json()["items"]) == 1


def test_weak_agent_is_blocked(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    pipeline = pipeline_headers(ci_idp)
    weak = ReferenceProfile(marker_leak_rate=0.2, secret_echo_rate=0.05)
    target_id = register(client, enterprise_idp, "weak-agent", weak)
    run = run_to_completion(client, pipeline, target_id, "0.9.0")
    decision = client.post(f"/v1/runs/{run['id']}/gate", headers=pipeline).json()
    assert decision["outcome"] == "fail"
    assessments = {
        a["category"]: a["verdict"] for a in decision["signed_report"]["report"]["assessments"]
    }
    assert assessments["marker_leakage"] == "breach"
    failed = client.get(
        f"/v1/runs/{run['id']}/results",
        params={"failed_only": True, "limit": 500},
        headers=pipeline,
    ).json()["items"]
    assert failed
    assert {f["category"] for f in failed} <= {"marker_leakage", "secret_echo"}


def test_production_release_needs_a_second_person(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    pipeline = pipeline_headers(ci_idp)
    target_id = register(client, enterprise_idp, "payments-agent", risk=Severity.CRITICAL)
    run = run_to_completion(client, pipeline, target_id, "5.0.0", environment="production")
    decision = client.post(f"/v1/runs/{run['id']}/gate", headers=pipeline).json()
    assert decision["outcome"] == "require_approval"

    operator = user_headers(enterprise_idp, "redteam-operator")
    refused = client.post(
        f"/v1/gate/decisions/{decision['id']}/approve", json={"reason": "ship it"}, headers=operator
    )
    assert refused.status_code == 403
    approver = user_headers(enterprise_idp, "release-approver", sub="carol@corp.test")
    approved = client.post(
        f"/v1/gate/decisions/{decision['id']}/approve",
        json={"reason": "reviewed the signed evidence"},
        headers=approver,
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["outcome"] == "approved"
    again = client.post(
        f"/v1/gate/decisions/{decision['id']}/approve", json={"reason": "twice?"}, headers=approver
    )
    assert again.status_code == 409


def test_operational_endpoints(client: TestClient, enterprise_idp: FakeIdp) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    headers = user_headers(enterprise_idp, "redteam-auditor")
    response = client.get(
        "/v1/gate/sample-size", params={"max_failure_rate": 0.05}, headers=headers
    )
    assert response.json()["zero_failure_probes"] == 73
    assert response.headers["x-content-type-options"] == "nosniff"
    traced = client.get("/healthz", headers={"X-Correlation-ID": "trace-123"})
    assert traced.headers["x-correlation-id"] == "trace-123"
    assert client.get("/v1/judges/llm", headers=headers).json() == {
        "enabled": False,
        "calibrated": False,
        "kappa": None,
        "binding": False,
    }
    calibrate = client.post(
        "/v1/judges/llm/calibration",
        json={"suite": "agent-baseline"},
        headers=user_headers(enterprise_idp, "redteam-operator"),
    )
    assert calibrate.status_code == 409
    metrics = client.get("/metrics").text
    assert "crt_http_request_duration_seconds" in metrics


def test_capacity_limit_returns_429(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    target_id = register(client, enterprise_idp)
    container.scheduler._max = 0
    response = client.post(
        "/v1/runs",
        json={"target_id": target_id, "target_version": "1", "suite": "agent-baseline"},
        headers=pipeline_headers(ci_idp),
    )
    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"
