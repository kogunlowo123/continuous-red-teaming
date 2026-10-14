"""The composite GitHub Action's client driving the real API (no network: routed into the app)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from continuous_red_teaming import gate_client
from continuous_red_teaming.domain.models import ReferenceProfile, Severity
from tests.conftest import FakeIdp, pipeline_headers, reference_registration, user_headers

pytestmark = pytest.mark.e2e


def routed(client: TestClient) -> gate_client.Transport:
    def transport(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        parts = urlsplit(url)
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        response = client.request(method, path, headers=headers, content=body)
        return response.status_code, response.content

    return transport


def register(client: TestClient, idp: FakeIdp, **kw: Any) -> str:
    response = client.post(
        "/v1/targets",
        json=reference_registration(**kw).model_dump(mode="json"),
        headers=user_headers(idp, "redteam-operator"),
    )
    return str(response.json()["id"])


def options(target_id: str, tmp_path: Path, **kw: Any) -> gate_client.Options:
    logs: list[str] = []
    values: dict[str, Any] = {
        "url": "https://redteam.corp.test",
        "target_id": target_id,
        "target_version": "7.0.0",
        "suite": "agent-baseline",
        "seed": 9,
        "poll_interval_s": 0.05,
        "timeout_s": 60,
        "report_file": tmp_path / "report.json",
        "summary_file": tmp_path / "summary.md",
        "output_file": tmp_path / "outputs.txt",
        "log": logs.append,
    }
    values.update(kw)
    return gate_client.Options(**values)


def token(idp: FakeIdp) -> str:
    return pipeline_headers(idp)["Authorization"].removeprefix("Bearer ")


def test_releasable_agent_exits_zero_and_writes_evidence(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp, tmp_path: Path
) -> None:
    target_id = register(client, enterprise_idp)
    api = gate_client.GateApi("https://redteam.corp.test", token(ci_idp), routed(client))
    assert gate_client.run_gate(api, options(target_id, tmp_path)) == 0
    report = json.loads((tmp_path / "report.json").read_text("utf-8"))
    assert report["report"]["outcome"] == "pass"
    outputs = (tmp_path / "outputs.txt").read_text("utf-8")
    assert "outcome=pass" in outputs
    assert "report-digest=sha256:" in outputs
    summary = (tmp_path / "summary.md").read_text("utf-8")
    assert "## Release gate: `pass`" in summary
    assert "| marker_leakage | pass |" in summary


def test_weak_agent_exits_one(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp, tmp_path: Path
) -> None:
    target_id = register(
        client, enterprise_idp, name="weak", profile=ReferenceProfile(marker_leak_rate=0.5)
    )
    api = gate_client.GateApi("https://redteam.corp.test", token(ci_idp), routed(client))
    assert gate_client.run_gate(api, options(target_id, tmp_path, seed=None)) == 1


def test_waits_for_human_approval(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp, tmp_path: Path
) -> None:
    target_id = register(client, enterprise_idp, name="critical", risk=Severity.CRITICAL)
    api = gate_client.GateApi("https://redteam.corp.test", token(ci_idp), routed(client))
    approver = user_headers(enterprise_idp, "release-approver", sub="dana@corp.test")
    approvals = {"done": False}

    def approve_while_waiting(_: float) -> None:
        if approvals["done"]:
            return
        decisions = client.get("/v1/gate/decisions", headers=approver).json()["items"]
        pending = [d for d in decisions if d["outcome"] == "require_approval"]
        if pending:
            client.post(
                f"/v1/gate/decisions/{pending[0]['id']}/approve",
                json={"reason": "change board approved"},
                headers=approver,
            )
            approvals["done"] = True

    opts = options(
        target_id,
        tmp_path,
        environment="production",
        approval_wait_s=30,
        sleep=approve_while_waiting,
    )
    assert gate_client.run_gate(api, opts) == 0
    assert "outcome=approved" in (tmp_path / "outputs.txt").read_text("utf-8")


def test_unreleasable_without_waiting(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp, tmp_path: Path
) -> None:
    target_id = register(client, enterprise_idp, name="critical-2", risk=Severity.CRITICAL)
    api = gate_client.GateApi("https://redteam.corp.test", token(ci_idp), routed(client))
    opts = options(target_id, tmp_path, environment="production", report_file=None)
    assert gate_client.run_gate(api, opts) == 1


def test_main_with_token_and_operational_errors(
    *,
    client: TestClient,
    enterprise_idp: FakeIdp,
    ci_idp: FakeIdp,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target_id = register(client, enterprise_idp)
    monkeypatch.setenv("CRT_GATE_TOKEN", token(ci_idp))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    argv = [
        "--url",
        "https://redteam.corp.test",
        "--target-id",
        target_id,
        "--target-version",
        "8.0.0",
        "--suite",
        "agent-baseline",
        "--poll-interval",
        "0.05",
        "--report-file",
        str(tmp_path / "r.json"),
    ]
    assert gate_client.main(argv, transport=routed(client)) == 0
    assert "outcome=pass" in (tmp_path / "out.txt").read_text("utf-8")

    unknown = [*argv[:3], "missing-target", *argv[4:]]
    assert gate_client.main(unknown, transport=routed(client)) == 2
    assert "could not be evaluated" in capsys.readouterr().err
