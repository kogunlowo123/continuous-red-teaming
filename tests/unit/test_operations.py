"""Settings, published contracts, persistence, scheduling and executor failure handling."""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from continuous_red_teaming import contracts
from continuous_red_teaming.application.executor import ProbeExecutor
from continuous_red_teaming.application.scheduler import RunScheduler
from continuous_red_teaming.application.service import RunRequest
from continuous_red_teaming.domain.errors import (
    AdapterError,
    CapacityError,
    ConflictError,
    DependencyUnavailableError,
    NotFoundError,
)
from continuous_red_teaming.domain.expansion import expand
from continuous_red_teaming.domain.models import (
    ProbeInvocation,
    ProbeOutcome,
    ReferenceProfile,
    RunStatus,
    Target,
    TargetKind,
    TargetRegistration,
    TargetResponse,
    ToolCall,
)
from continuous_red_teaming.domain.suites import SuiteCatalog
from continuous_red_teaming.infrastructure.database import (
    SqlDecisionRepository,
    SqlRunRepository,
    SqlTargetRepository,
    create_schema,
    make_engine,
)
from continuous_red_teaming.judges.panel import JudgePanel
from continuous_red_teaming.observability.metrics import RedTeamMetrics
from continuous_red_teaming.runtime.container import Container, build_container
from tests.conftest import ROOT, FakeIdp, make_settings, reference_registration, resolvers

# ----------------------------------------------------------------------- settings


def test_settings_validation(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="dev_ephemeral_keys cannot"):
        make_settings(tmp_path, environment="production")
    with pytest.raises(ValidationError, match="CRT_AUDIT_KEY_FILE"):
        make_settings(tmp_path, dev_ephemeral_keys=False)
    with pytest.raises(ValidationError, match="allow_insecure_targets"):
        make_settings(
            tmp_path,
            environment="production",
            dev_ephemeral_keys=False,
            audit_key_file=tmp_path / "k.pem",
            allow_insecure_targets=True,
        )
    with pytest.raises(ValidationError, match="CRT_FABRIC_ISSUER"):
        make_settings(tmp_path, fabric_url="https://identity.corp.test")
    with pytest.raises(ValidationError, match="no caller could log in"):
        make_settings(tmp_path, trusted_issuers=[])
    ok = make_settings(tmp_path, public_url="https://redteam.corp.test/")
    assert ok.public_url_str == "https://redteam.corp.test"


async def test_container_with_file_keys_and_retired_keys(
    tmp_path: Path, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    key = Ed25519PrivateKey.generate()
    key_file = tmp_path / "audit-2026-10.pem"
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    retired = Ed25519PrivateKey.generate().public_key()
    raw = retired.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    settings = make_settings(
        tmp_path,
        environment="production",
        dev_ephemeral_keys=False,
        audit_key_file=key_file,
        retired_report_keys={"audit-2026-07": base64.b64encode(raw).decode()},
        fabric_url="https://identity.corp.test",
        fabric_issuer="https://identity.corp.test",
    )
    built = await build_container(settings, issuer_resolvers=resolvers(enterprise_idp, ci_idp))
    try:
        kids = {k["kid"] for k in built.service.signer.jwks()["keys"]}
        assert kids == {"audit-2026-10", "audit-2026-07"}
    finally:
        await built.aclose()


async def test_container_rejects_non_ed25519_audit_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_file = tmp_path / "bad.pem"
    key_file.write_bytes(pem)
    settings = make_settings(tmp_path, dev_ephemeral_keys=False, audit_key_file=key_file)
    with pytest.raises(ValueError, match="Ed25519"):
        await build_container(settings)


# ---------------------------------------------------------------------- contracts


def test_published_contracts_are_current() -> None:
    assert contracts.main(["--check"], root=ROOT) == 0


def test_contract_drift_is_detected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert contracts.main(["--check"], root=tmp_path) == 1
    assert "stale contracts" in capsys.readouterr().err
    assert contracts.main([], root=tmp_path) == 0
    assert contracts.main(["--check"], root=tmp_path) == 0


# -------------------------------------------------------------------- persistence


async def test_repositories_round_trip(tmp_path: Path) -> None:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'p.db'}")
    await create_schema(engine)
    await create_schema(engine)
    targets, runs, decisions = (
        SqlTargetRepository(engine),
        SqlRunRepository(engine),
        SqlDecisionRepository(engine),
    )
    now = datetime.now(UTC)
    target = Target(
        **reference_registration().model_dump(), id="t1", created_at=now, created_by="a"
    )
    await targets.add(target)
    assert await targets.get("t1") == target
    assert await targets.get("missing") is None
    assert [t.id for t in await targets.list()] == ["t1"]
    with pytest.raises(ConflictError):
        await targets.add(target.model_copy(update={"id": "t2"}))
    from continuous_red_teaming.domain.models import Run

    run = Run(
        id="r1",
        target_id="t1",
        target_version="1",
        suite_name="s",
        suite_version="1",
        suite_digest="sha256:x",
        seed=1,
        environment="staging",
        status=RunStatus.QUEUED,
        requested_by="a",
        created_at=now,
    )
    await runs.add(run)
    with pytest.raises(NotFoundError):
        await runs.update(run.model_copy(update={"id": "missing"}))
    assert await runs.get("missing") is None
    await runs.add_results([])
    assert await runs.list(target_id="t1", status=RunStatus.QUEUED) == [run]
    assert await decisions.get("missing") is None
    assert await decisions.list(target_id="t1") == []
    await engine.dispose()


# ------------------------------------------------------------------------ executor


class FlakyTarget:
    """Fails a configurable number of times per session before answering."""

    def __init__(self, failures: int, error: Exception) -> None:
        self.failures = failures
        self.error = error
        self.calls: dict[str, int] = {}

    async def invoke(self, invocation: ProbeInvocation) -> TargetResponse:
        count = self.calls.get(invocation.session_id, 0) + 1
        self.calls[invocation.session_id] = count
        if count <= self.failures:
            raise self.error
        return TargetResponse(output="ok")


class SlowTarget:
    async def invoke(self, invocation: ProbeInvocation) -> TargetResponse:
        await asyncio.sleep(1.0)
        return TargetResponse(output="late")


class FakeTrace:
    def __init__(self, calls: list[ToolCall] | None = None, fail: bool = False) -> None:
        self.calls = calls or []
        self.fail = fail

    async def tool_calls(self, session_id: str) -> list[ToolCall]:
        if self.fail:
            raise AdapterError("trace store down")
        return self.calls


def probes(limit: int = 6) -> list[Any]:
    suite = SuiteCatalog.from_directory(ROOT / "suites").get("agent-baseline")
    return expand(suite, 1)[:limit]


def executor(**kw: Any) -> ProbeExecutor:
    policy = PolicyEngine(PolicySet.from_file(ROOT / "policies" / "target-tool-policy.yaml"))
    return ProbeExecutor(JudgePanel.build(policy), metrics=RedTeamMetrics(), **kw)


async def test_executor_retries_transient_errors() -> None:
    target = FlakyTarget(1, AdapterError("blip"))
    results = await executor(retries=1).execute("r", probes(3), target)
    assert all(r.outcome is ProbeOutcome.PASS and r.attempts == 2 for r in results)


async def test_executor_does_not_retry_contract_violations() -> None:
    target = FlakyTarget(5, AdapterError("bad reply", retryable=False))
    results = await executor(retries=3).execute("r", probes(2), target)
    assert all(r.outcome is ProbeOutcome.ERROR and r.attempts == 1 for r in results)
    assert results[0].error == "bad reply"


async def test_executor_timeouts_and_credential_failures() -> None:
    results = await executor(retries=0).execute("r", probes(1), SlowTarget(), timeout_s=0.01)
    assert results[0].outcome is ProbeOutcome.ERROR
    assert "did not answer" in str(results[0].error)
    no_credential = FlakyTarget(9, DependencyUnavailableError("token missing"))
    failed = await executor().execute("r", probes(1), no_credential)
    assert failed[0].error == "token missing"


async def test_executor_aborts_after_consecutive_errors() -> None:
    target = FlakyTarget(99, AdapterError("down"))
    results = await executor(concurrency=1, retries=0, abort_after_consecutive_errors=2).execute(
        "r", probes(6), target
    )
    assert sum(len(t) for t in [target.calls]) == 2
    assert [r.attempts for r in results] == [1, 1, 0, 0, 0, 0]
    assert all(r.outcome is ProbeOutcome.ERROR for r in results)


async def test_executor_merges_external_traces() -> None:
    shell = ToolCall(name="shell.exec")
    target = FlakyTarget(0, AdapterError("unused"))
    forbidden = [p for p in probes(400) if p.forbidden_tools == ("shell.*",)][:1]
    results = await executor().execute("r", forbidden, target, trace_source=FakeTrace([shell]))
    assert results[0].outcome is ProbeOutcome.FAIL
    assert results[0].evidence is not None
    assert results[0].evidence.trace_source == "external"
    unavailable = await executor().execute(
        "r", forbidden, target, trace_source=FakeTrace(fail=True)
    )
    assert unavailable[0].outcome is ProbeOutcome.ERROR
    assert "trace unavailable" in str(unavailable[0].error)


def test_executor_limits_are_validated() -> None:
    with pytest.raises(ValueError, match="limits"):
        executor(concurrency=0)


# ----------------------------------------------------------------------- scheduler


async def test_scheduler_capacity_and_completion(container: Container) -> None:
    service = container.service
    target = await service.register_target(reference_registration(), actor="a")
    scheduler = RunScheduler(service, max_active_runs=1)
    run = await service.create_run(
        RunRequest(target_id=target.id, target_version="1", suite="agent-baseline"), actor="a"
    )
    scheduler.submit(run.id)
    assert scheduler.active == 1
    with pytest.raises(CapacityError):
        scheduler.ensure_capacity()
    await scheduler.wait(run.id)
    await asyncio.sleep(0)
    assert scheduler.active == 0
    assert (await service.get_run(run.id)).status is RunStatus.COMPLETED
    await scheduler.wait("unknown")
    with pytest.raises(ValueError, match="at least 1"):
        RunScheduler(service, max_active_runs=0)


async def test_scheduler_cancellation_aborts_runs(container: Container) -> None:
    service = container.service
    target = await service.register_target(
        TargetRegistration(
            name="slow",
            kind=TargetKind.REFERENCE,
            reference_profile=ReferenceProfile(),
            owner="team",
        ),
        actor="a",
    )
    scheduler = RunScheduler(service)
    entered = asyncio.Event()

    async def stalled(*_: Any, **__: Any) -> list[Any]:
        entered.set()
        await asyncio.sleep(30)
        return []

    run = await service.create_run(
        RunRequest(target_id=target.id, target_version="1", suite="agent-baseline"), actor="a"
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("continuous_red_teaming.application.service.ProbeExecutor.execute", stalled)
        scheduler.submit(run.id)
        await asyncio.wait_for(entered.wait(), timeout=10)
        await scheduler.aclose()
    finished = await service.get_run(run.id)
    assert finished.status is RunStatus.ABORTED
    assert finished.error == "cancelled"


async def test_unrecordable_abort_is_left_for_restart_recovery(container: Container) -> None:
    service = container.service
    target = await service.register_target(reference_registration(), actor="a")
    run = await service.create_run(
        RunRequest(target_id=target.id, target_version="1", suite="agent-baseline"), actor="a"
    )
    entered = asyncio.Event()

    async def stalled(*_: Any, **__: Any) -> list[Any]:
        entered.set()
        await asyncio.sleep(30)
        return []

    async def broken_finish(*_: Any, **__: Any) -> Any:
        raise OSError("database went away")

    scheduler = RunScheduler(service)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("continuous_red_teaming.application.service.ProbeExecutor.execute", stalled)
        scheduler.submit(run.id)
        await asyncio.wait_for(entered.wait(), timeout=10)
        patch.setattr(service, "_finish", broken_finish)
        await scheduler.aclose()
    assert (await service.get_run(run.id)).status is RunStatus.RUNNING
    assert await service.recover_interrupted() == 1
    assert (await service.get_run(run.id)).status is RunStatus.ABORTED


async def test_scheduler_survives_crashing_runs(container: Container) -> None:
    scheduler = RunScheduler(container.service)
    scheduler.submit("does-not-exist")
    await scheduler.wait("does-not-exist")
    assert scheduler.active == 0


def test_shipped_provider_config_resolves_and_fails_closed() -> None:
    from agentic_core.models.factory import ProvidersConfig, build_providers, env_references

    path = ROOT / "configs" / "providers.yaml"
    names = env_references(path.read_text("utf-8"))
    env = {name: "1.5" if name.endswith("_MTOK") else f"value-{name.lower()}" for name in names}
    env |= {"GCP_ACCESS_TOKEN": "ya29.test", "ANTHROPIC_API_KEY": "test-only"}
    config = ProvidersConfig.from_file(path, env=env)
    providers = build_providers(config, env=env)
    assert [p.profile.name for p in providers] == ["gemini-judge", "claude-judge"]
    assert all(p.profile.max_classification == 2 for p in providers)
    with pytest.raises(ValueError, match="unset environment variables"):
        ProvidersConfig.from_file(path, env={})
