"""Fault injection: the platform fails closed and never turns missing evidence into a pass."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from continuous_red_teaming.api.app import create_app
from continuous_red_teaming.application.service import RunRequest
from continuous_red_teaming.domain.errors import DependencyUnavailableError
from continuous_red_teaming.domain.models import (
    CategoryVerdict,
    GateOutcome,
    ProbeOutcome,
    RunStatus,
    TargetKind,
    TargetRegistration,
)
from continuous_red_teaming.infrastructure.database import make_engine
from continuous_red_teaming.runtime.container import Container, build_container
from continuous_red_teaming.security.access import Action
from continuous_red_teaming.security.auth import Principal, PrincipalKind
from tests.conftest import FakeIdp, make_settings, reference_registration, resolvers
from tests.unit.test_service import PIPELINE

pytestmark = pytest.mark.chaos


def refusing(_: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused")


def test_database_outage_flips_readiness(client: TestClient) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    assert client.get("/readyz").status_code == 200
    healthy = container.engine
    container.engine = make_engine("sqlite+aiosqlite:////nonexistent/dir/db.sqlite")
    try:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200
    finally:
        container.engine = healthy


async def test_unreachable_target_is_insufficient_evidence_not_a_pass(
    tmp_path: Path, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    settings = make_settings(tmp_path, abort_after_consecutive_errors=5)
    built = await build_container(
        settings,
        issuer_resolvers=resolvers(enterprise_idp, ci_idp),
        http=httpx.AsyncClient(transport=httpx.MockTransport(refusing)),
    )
    try:
        target = await built.service.register_target(
            TargetRegistration(
                name="offline",
                kind=TargetKind.HTTP,
                endpoint="https://agents.corp.test/invoke",
                owner="team",
            ),
            actor="alice",
        )
        run = await built.service.create_run(
            RunRequest(target_id=target.id, target_version="1", suite="agent-baseline"), actor="a"
        )
        finished = await built.service.execute_run(run.id)
        assert finished.status is RunStatus.COMPLETED
        assert finished.summary is not None
        assert finished.summary.errors == finished.summary.total
        decision = await built.service.evaluate_gate(run.id, requester=PIPELINE)
        assert decision.outcome is GateOutcome.FAIL
        assert {a.verdict for a in decision.signed_report.report.assessments} == {
            CategoryVerdict.INSUFFICIENT_EVIDENCE
        }
        results = await built.service.run_results(run.id, limit=1000)
        assert sum(1 for r in results if r.attempts == 0) > 300  # not sent after the breaker
    finally:
        await built.aclose()


async def test_trace_store_outage_makes_probes_inconclusive(
    tmp_path: Path, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    def agent_up_trace_down(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/trace":
            return httpx.Response(503)
        return httpx.Response(200, json={"output": "ok", "status": "completed"})

    built = await build_container(
        make_settings(tmp_path),
        issuer_resolvers=resolvers(enterprise_idp, ci_idp),
        http=httpx.AsyncClient(transport=httpx.MockTransport(agent_up_trace_down)),
    )
    try:
        target = await built.service.register_target(
            TargetRegistration(
                name="traced",
                kind=TargetKind.HTTP,
                endpoint="https://agents.corp.test/invoke",
                trace_endpoint="https://agents.corp.test/trace",
                owner="team",
            ),
            actor="alice",
        )
        run = await built.service.create_run(
            RunRequest(target_id=target.id, target_version="1", suite="agent-baseline"), actor="a"
        )
        await built.service.execute_run(run.id)
        results = await built.service.run_results(run.id, limit=1000)
        assert all(r.outcome is ProbeOutcome.ERROR for r in results)
        assert any("trace unavailable" in str(r.error) for r in results)
    finally:
        await built.aclose()


async def test_audit_failure_blocks_the_gate_decision(container: Container) -> None:
    service = container.service
    target = await service.register_target(reference_registration(), actor="alice")
    run = await service.create_run(
        RunRequest(target_id=target.id, target_version="1", suite="agent-baseline"), actor="a"
    )
    await service.execute_run(run.id)

    async def broken_append(_: object) -> None:
        raise OSError("disk full")

    container.audit._sink.append = broken_append  # type: ignore[method-assign]
    with pytest.raises(OSError, match="disk full"):
        await service.evaluate_gate(run.id, requester=PIPELINE)
    assert await service.list_decisions(target_id=target.id) == []


async def test_identity_fabric_outage_fails_closed(
    tmp_path: Path, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    settings = make_settings(
        tmp_path,
        fabric_url="https://identity.corp.test",
        fabric_issuer="https://identity.corp.test",
    )

    async def factory() -> Container:
        return await build_container(
            settings,
            issuer_resolvers=resolvers(enterprise_idp, ci_idp),
            http=httpx.AsyncClient(transport=httpx.MockTransport(refusing)),
        )

    agent = Principal(
        subject="spiffe://corp/agent/a/b",
        issuer="https://identity.corp.test",
        kind=PrincipalKind.AGENT,
        credential="t",
    )
    built = await factory()
    try:
        with pytest.raises(DependencyUnavailableError):
            await built.access.authorize(agent, Action.RUNS_READ)
    finally:
        await built.aclose()

    token = FakeIdp("https://identity.corp.test").mint(sub="spiffe://corp/agent/a/b")
    with TestClient(create_app(factory)) as client:
        response = client.get("/v1/suites", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 503
        assert response.json()["error"] == "temporarily_unavailable"


async def test_restart_recovers_interrupted_runs(
    tmp_path: Path, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    settings = make_settings(tmp_path)
    first = await build_container(settings, issuer_resolvers=resolvers(enterprise_idp, ci_idp))
    target = await first.service.register_target(reference_registration(), actor="a")
    run = await first.service.create_run(
        RunRequest(target_id=target.id, target_version="1", suite="agent-baseline"), actor="a"
    )
    await first.aclose()

    async def factory() -> Container:
        return await build_container(settings, issuer_resolvers=resolvers(enterprise_idp, ci_idp))

    with TestClient(create_app(factory)) as client:
        container = client.app.state.container  # type: ignore[attr-defined]
        restarted = client.portal.call(container.service.get_run, run.id)  # type: ignore[union-attr]
        assert restarted.status is RunStatus.ABORTED
        assert restarted.error == "interrupted by restart"
