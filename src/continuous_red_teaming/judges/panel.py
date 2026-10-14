"""Combines the judges a scenario asks for into one probe outcome."""

from __future__ import annotations

from collections.abc import Mapping

from agentic_core.policy import PolicyEngine

from continuous_red_teaming.domain.models import (
    JudgeName,
    JudgeVerdict,
    Probe,
    ProbeOutcome,
    TargetResponse,
    VerdictOutcome,
)
from continuous_red_teaming.judges.base import Judge
from continuous_red_teaming.judges.llm import LlmRubricJudge
from continuous_red_teaming.judges.markers import MarkerLeakageJudge
from continuous_red_teaming.judges.tools import (
    ApprovalBypassJudge,
    ForbiddenToolJudge,
    PolicyViolationJudge,
    ToolPolicy,
)


class JudgePanel:
    def __init__(self, judges: Mapping[JudgeName, Judge]) -> None:
        self._judges = dict(judges)

    @classmethod
    def build(cls, tool_policy: PolicyEngine, llm: LlmRubricJudge | None = None) -> JudgePanel:
        policy = ToolPolicy(tool_policy)
        judges: dict[JudgeName, Judge] = {
            JudgeName.MARKER_LEAKAGE: MarkerLeakageJudge(),
            JudgeName.FORBIDDEN_TOOL: ForbiddenToolJudge(),
            JudgeName.POLICY_VIOLATION: PolicyViolationJudge(policy),
            JudgeName.APPROVAL_BYPASS: ApprovalBypassJudge(policy),
        }
        if llm is not None:
            judges[JudgeName.LLM_RUBRIC] = llm
        return cls(judges)

    def has(self, name: JudgeName) -> bool:
        return name in self._judges

    async def assess(
        self, probe: Probe, response: TargetResponse
    ) -> tuple[ProbeOutcome, tuple[JudgeVerdict, ...]]:
        verdicts: list[JudgeVerdict] = []
        for name in probe.judges:
            judge = self._judges.get(name)
            if judge is None:
                verdicts.append(
                    JudgeVerdict(
                        judge=name,
                        outcome=VerdictOutcome.ABSTAIN,
                        evidence=("judge not configured on this platform",),
                        advisory=True,
                    )
                )
                continue
            verdicts.append(await judge.judge(probe, response))
        failed = any(v.outcome is VerdictOutcome.FAIL and not v.advisory for v in verdicts)
        return (ProbeOutcome.FAIL if failed else ProbeOutcome.PASS), tuple(verdicts)
