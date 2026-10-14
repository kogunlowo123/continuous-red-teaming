"""The platform recovers known weakness rates: judges plus statistics measure what they claim.

A reference agent fails each category with a configured probability. Over
the full baseline suite, every configured rate must fall inside the Wilson
interval computed from the measured failures. The check uses 99.9% intervals
so it holds across seeds rather than for one lucky seed.
"""

from __future__ import annotations

import pytest
from agentic_core.policy import PolicyEngine, PolicySet

from continuous_red_teaming.adapters.reference import ReferenceAgent
from continuous_red_teaming.application.executor import ProbeExecutor
from continuous_red_teaming.domain.expansion import expand
from continuous_red_teaming.domain.models import Category, ReferenceProfile
from continuous_red_teaming.domain.statistics import wilson_interval
from continuous_red_teaming.domain.suites import SuiteCatalog
from continuous_red_teaming.judges.panel import JudgePanel
from continuous_red_teaming.observability.metrics import RedTeamMetrics
from continuous_red_teaming.scoring.scorer import summarize
from tests.conftest import ROOT

POLICY = PolicyEngine(PolicySet.from_file(ROOT / "policies" / "target-tool-policy.yaml"))
SUITE = SuiteCatalog.from_directory(ROOT / "suites").get("agent-baseline")


def configured(profile: ReferenceProfile, category: Category) -> float:
    return {
        Category.MARKER_LEAKAGE: profile.marker_leak_rate,
        Category.SECRET_ECHO: profile.secret_echo_rate,
        Category.FORBIDDEN_TOOL: profile.forbidden_tool_rate,
        Category.POLICY_VIOLATION: profile.forbidden_tool_rate,
        Category.APPROVAL_BYPASS: profile.approval_bypass_rate,
    }[category]


@pytest.mark.parametrize(
    ("profile", "seed"),
    [
        (
            ReferenceProfile(
                marker_leak_rate=0.3,
                secret_echo_rate=0.1,
                forbidden_tool_rate=0.2,
                approval_bypass_rate=0.25,
                seed=1,
            ),
            7,
        ),
        (
            ReferenceProfile(
                marker_leak_rate=0.05,
                secret_echo_rate=0.5,
                forbidden_tool_rate=0.02,
                approval_bypass_rate=0.6,
                seed=2,
            ),
            11,
        ),
        (ReferenceProfile(seed=3), 13),
    ],
)
async def test_configured_rates_fall_inside_measured_intervals(
    profile: ReferenceProfile, seed: int
) -> None:
    executor = ProbeExecutor(JudgePanel.build(POLICY), metrics=RedTeamMetrics())
    results = await executor.execute(
        "accuracy", expand(SUITE, seed), ReferenceAgent(profile, POLICY)
    )
    summary = summarize(results, seed=seed)
    assert summary.errors == 0
    for stats in summary.categories:
        low, high = wilson_interval(stats.failures, stats.conclusive, 0.999)
        assert low <= configured(profile, stats.category) <= high, stats
