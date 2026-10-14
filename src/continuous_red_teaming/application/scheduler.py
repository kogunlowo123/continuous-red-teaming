"""Background execution of queued runs with a bound on concurrent runs."""

from __future__ import annotations

import asyncio
import contextlib

from agentic_core.observability import get_logger

from continuous_red_teaming.application.service import RedTeamService
from continuous_red_teaming.domain.errors import CapacityError

log = get_logger("continuous_red_teaming.scheduler")


class RunScheduler:
    def __init__(self, service: RedTeamService, *, max_active_runs: int = 4) -> None:
        if max_active_runs < 1:
            raise ValueError("max_active_runs must be at least 1")
        self._service = service
        self._max = max_active_runs
        self._tasks: dict[str, asyncio.Task[None]] = {}

    @property
    def active(self) -> int:
        return len(self._tasks)

    def ensure_capacity(self) -> None:
        if len(self._tasks) >= self._max:
            raise CapacityError(f"{self._max} runs are already executing; retry later")

    def submit(self, run_id: str) -> None:
        self.ensure_capacity()
        task = asyncio.create_task(self._run(run_id), name=f"run-{run_id}")
        self._tasks[run_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(run_id, None))

    async def _run(self, run_id: str) -> None:
        try:
            run = await self._service.execute_run(run_id)
            log.info("run_finished", run_id=run_id, status=run.status.value)
        except asyncio.CancelledError:
            raise
        except Exception:
            # execute_run records failures itself; this guards the background task.
            log.exception("run_crashed", run_id=run_id)

    async def wait(self, run_id: str) -> None:
        task = self._tasks.get(run_id)
        if task is not None:
            await asyncio.shield(task)

    async def aclose(self) -> None:
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
