"""Judge contract."""

from __future__ import annotations

from typing import Protocol

from continuous_red_teaming.domain.models import JudgeName, JudgeVerdict, Probe, TargetResponse


class Judge(Protocol):
    name: JudgeName

    async def judge(self, probe: Probe, response: TargetResponse) -> JudgeVerdict: ...
