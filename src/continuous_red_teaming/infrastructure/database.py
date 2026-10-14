"""SQLAlchemy Core persistence. PostgreSQL in production; SQLite in tests.

Aggregates are stored as validated JSON documents next to the indexed
columns the queries need, so the domain model can evolve without a
migration for every field while lookups stay indexed.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from continuous_red_teaming.domain.errors import ConflictError, NotFoundError
from continuous_red_teaming.domain.models import (
    GateDecision,
    ProbeOutcome,
    ProbeResult,
    Run,
    RunStatus,
    Target,
)

metadata = MetaData()

targets = Table(
    "targets",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("name", String(64), nullable=False, unique=True),
    Column("kind", String(16), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("document", Text, nullable=False),
)

runs = Table(
    "runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("target_id", String(64), nullable=False),
    Column("target_version", String(64), nullable=False),
    Column("suite_name", String(64), nullable=False),
    Column("status", String(16), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("document", Text, nullable=False),
    Index("ix_runs_target_created", "target_id", "created_at"),
    Index("ix_runs_status", "status"),
)

probe_results = Table(
    "probe_results",
    metadata,
    Column("run_id", String(64), primary_key=True),
    Column("probe_id", String(160), primary_key=True),
    Column("scenario_id", String(64), nullable=False),
    Column("category", String(32), nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("document", Text, nullable=False),
    Index("ix_probe_results_outcome", "run_id", "outcome"),
)

gate_decisions = Table(
    "gate_decisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(64), nullable=False),
    Column("target_id", String(64), nullable=False),
    Column("target_version", String(64), nullable=False),
    Column("outcome", String(24), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("document", Text, nullable=False),
    Index("ix_gate_target_created", "target_id", "created_at"),
    Index("ix_gate_run", "run_id"),
)

schema_version = Table(
    "schema_version",
    metadata,
    Column("version", Integer, primary_key=True),
)

SCHEMA_VERSION = 1


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        current = (await conn.execute(select(schema_version.c.version))).scalar()
        if current is None:
            await conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))


class SqlTargetRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, target: Target) -> None:
        async with self._engine.begin() as conn:
            clash = (
                await conn.execute(select(targets.c.id).where(targets.c.name == target.name))
            ).first()
            if clash:
                raise ConflictError(f"target {target.name} already registered")
            await conn.execute(
                insert(targets).values(
                    id=target.id,
                    name=target.name,
                    kind=target.kind.value,
                    created_at=target.created_at,
                    document=target.model_dump_json(),
                )
            )

    async def get(self, target_id: str) -> Target | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(targets.c.document).where(targets.c.id == target_id))
            ).first()
        return Target.model_validate_json(row[0]) if row else None

    async def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Target]:
        query = select(targets.c.document).order_by(targets.c.name).limit(limit).offset(offset)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [Target.model_validate_json(r[0]) for r in rows]


class SqlRunRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, run: Run) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(runs).values(
                    id=run.id,
                    target_id=run.target_id,
                    target_version=run.target_version,
                    suite_name=run.suite_name,
                    status=run.status.value,
                    created_at=run.created_at,
                    document=run.model_dump_json(),
                )
            )

    async def update(self, run: Run) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(runs)
                .where(runs.c.id == run.id)
                .values(status=run.status.value, document=run.model_dump_json())
            )
            if result.rowcount == 0:
                raise NotFoundError(f"run {run.id} not found")

    async def get(self, run_id: str) -> Run | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(select(runs.c.document).where(runs.c.id == run_id))).first()
        return Run.model_validate_json(row[0]) if row else None

    async def list(
        self,
        *,
        target_id: str | None = None,
        status: RunStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[Run]:
        query = (
            select(runs.c.document)
            .order_by(runs.c.created_at.desc(), runs.c.id)
            .limit(limit)
            .offset(offset)
        )
        if target_id is not None:
            query = query.where(runs.c.target_id == target_id)
        if status is not None:
            query = query.where(runs.c.status == status.value)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [Run.model_validate_json(r[0]) for r in rows]

    async def add_results(self, results: Sequence[ProbeResult]) -> None:
        if not results:
            return
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(probe_results),
                [
                    {
                        "run_id": r.run_id,
                        "probe_id": r.probe_id,
                        "scenario_id": r.scenario_id,
                        "category": r.category.value,
                        "outcome": r.outcome.value,
                        "document": r.model_dump_json(),
                    }
                    for r in results
                ],
            )

    async def results(
        self, run_id: str, *, failed_only: bool = False, limit: int = 1000, offset: int = 0
    ) -> Sequence[ProbeResult]:
        query = (
            select(probe_results.c.document)
            .where(probe_results.c.run_id == run_id)
            .order_by(probe_results.c.probe_id)
            .limit(limit)
            .offset(offset)
        )
        if failed_only:
            query = query.where(probe_results.c.outcome == ProbeOutcome.FAIL.value)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [ProbeResult.model_validate_json(r[0]) for r in rows]


class SqlDecisionRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, decision: GateDecision) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(gate_decisions).values(
                    id=decision.id,
                    run_id=decision.run_id,
                    target_id=decision.target_id,
                    target_version=decision.target_version,
                    outcome=decision.outcome.value,
                    created_at=decision.created_at,
                    document=decision.model_dump_json(),
                )
            )

    async def update(self, decision: GateDecision) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(gate_decisions)
                .where(gate_decisions.c.id == decision.id)
                .values(outcome=decision.outcome.value, document=decision.model_dump_json())
            )
            if result.rowcount == 0:
                raise NotFoundError(f"decision {decision.id} not found")

    async def get(self, decision_id: str) -> GateDecision | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(gate_decisions.c.document).where(gate_decisions.c.id == decision_id)
                )
            ).first()
        return GateDecision.model_validate_json(row[0]) if row else None

    async def list(
        self, *, target_id: str | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[GateDecision]:
        query = (
            select(gate_decisions.c.document)
            .order_by(gate_decisions.c.created_at.desc(), gate_decisions.c.id)
            .limit(limit)
            .offset(offset)
        )
        if target_id is not None:
            query = query.where(gate_decisions.c.target_id == target_id)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [GateDecision.model_validate_json(r[0]) for r in rows]


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
