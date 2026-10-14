"""Ports the application layer depends on. Adapters live in infrastructure and adapters."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from continuous_red_teaming.domain.models import (
    GateDecision,
    ProbeInvocation,
    ProbeResult,
    Run,
    RunStatus,
    Target,
    TargetResponse,
    ToolCall,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class TargetRepository(Protocol):
    async def add(self, target: Target) -> None: ...

    async def get(self, target_id: str) -> Target | None: ...

    async def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Target]: ...


class RunRepository(Protocol):
    async def add(self, run: Run) -> None: ...

    async def update(self, run: Run) -> None: ...

    async def get(self, run_id: str) -> Run | None: ...

    async def list(
        self,
        *,
        target_id: str | None = None,
        status: RunStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[Run]: ...

    async def add_results(self, results: Sequence[ProbeResult]) -> None: ...

    async def results(
        self, run_id: str, *, failed_only: bool = False, limit: int = 1000, offset: int = 0
    ) -> Sequence[ProbeResult]: ...


class DecisionRepository(Protocol):
    async def add(self, decision: GateDecision) -> None: ...

    async def update(self, decision: GateDecision) -> None: ...

    async def get(self, decision_id: str) -> GateDecision | None: ...

    async def list(
        self, *, target_id: str | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[GateDecision]: ...


class TargetAdapter(Protocol):
    """Invokes one target with one probe and normalizes the answer."""

    async def invoke(self, invocation: ProbeInvocation) -> TargetResponse: ...


class TraceSource(Protocol):
    """Independent record of tool calls a target made in a session (e.g. a gateway audit)."""

    async def tool_calls(self, session_id: str) -> Sequence[ToolCall]: ...
