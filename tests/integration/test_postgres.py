"""Repositories and a full run against a real PostgreSQL (CI service container).

Runs when CRT_TEST_DATABASE_URL points at PostgreSQL, e.g.
postgresql+asyncpg://redteam:redteam@localhost:5432/redteam
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from continuous_red_teaming.application.service import RunRequest
from continuous_red_teaming.domain.models import GateOutcome, RunStatus, Target
from continuous_red_teaming.infrastructure.database import (
    SqlTargetRepository,
    create_schema,
    make_engine,
)
from continuous_red_teaming.runtime.container import build_container
from tests.conftest import FakeIdp, make_settings, reference_registration, resolvers
from tests.unit.test_service import PIPELINE

URL = os.environ.get("CRT_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL.startswith("postgresql"), reason="PostgreSQL not configured"),
]


async def test_schema_is_idempotent_and_targets_round_trip() -> None:
    engine = make_engine(URL)
    await create_schema(engine)
    await create_schema(engine)
    repo = SqlTargetRepository(engine)
    stamp = f"{datetime.now(UTC).timestamp():.0f}"
    target = Target(
        **reference_registration(f"pg-{stamp}").model_dump(),
        id=f"pg-{stamp}",
        created_at=datetime.now(UTC),
        created_by="ci",
    )
    await repo.add(target)
    assert await repo.get(target.id) == target
    await engine.dispose()


async def test_full_run_and_gate_on_postgres(
    tmp_path: Path, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    built = await build_container(
        make_settings(tmp_path, database_url=URL),
        issuer_resolvers=resolvers(enterprise_idp, ci_idp),
    )
    try:
        stamp = f"{datetime.now(UTC).timestamp():.0f}"
        target = await built.service.register_target(
            reference_registration(f"pg-run-{stamp}"), actor="ci"
        )
        run = await built.service.create_run(
            RunRequest(target_id=target.id, target_version="1.0.0", suite="agent-baseline"),
            actor="ci",
        )
        finished = await built.service.execute_run(run.id)
        assert finished.status is RunStatus.COMPLETED
        assert len(await built.service.run_results(run.id, limit=1000)) == 394
        decision = await built.service.evaluate_gate(run.id, requester=PIPELINE)
        assert decision.outcome is GateOutcome.PASS
        assert (
            await built.service.get_decision(decision.id)
        ).signed_report == decision.signed_report
    finally:
        await built.aclose()
