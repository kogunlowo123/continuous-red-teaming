"""Latency budgets for hot paths. Loose enough for shared CI runners."""

from __future__ import annotations

import time

import pytest
from agentic_core.policy import PolicyEngine, PolicySet

from continuous_red_teaming.adapters.reference import ReferenceAgent
from continuous_red_teaming.application.executor import ProbeExecutor
from continuous_red_teaming.domain.expansion import expand
from continuous_red_teaming.domain.models import ReferenceProfile, TargetResponse
from continuous_red_teaming.domain.suites import SuiteCatalog
from continuous_red_teaming.judges.markers import disclosure_forms
from continuous_red_teaming.judges.panel import JudgePanel
from continuous_red_teaming.observability.metrics import RedTeamMetrics
from continuous_red_teaming.scoring.scorer import summarize
from tests.conftest import ROOT

pytestmark = pytest.mark.performance

SUITE = SuiteCatalog.from_directory(ROOT / "suites").get("agent-baseline")
POLICY = PolicyEngine(PolicySet.from_file(ROOT / "policies" / "target-tool-policy.yaml"))


def test_expansion_budget() -> None:
    started = time.perf_counter()
    for seed in range(10):
        expand(SUITE, seed)
    per_suite_ms = (time.perf_counter() - started) * 1000 / 10
    assert per_suite_ms < 250


def test_marker_detection_throughput() -> None:
    marker = "CANARY-6a1f0c3e-2b4d-4e8f-9a7b-5c3d1e0f2a4b"
    text = "Routine summary of the ticket history and next steps for the team. " * 120
    started = time.perf_counter()
    for _ in range(200):
        disclosure_forms(marker, text)
    per_check_ms = (time.perf_counter() - started) * 1000 / 200
    assert per_check_ms < 10


async def test_full_suite_in_process_budget() -> None:
    probes = expand(SUITE, 3)
    agent = ReferenceAgent(ReferenceProfile(marker_leak_rate=0.2), POLICY)
    executor = ProbeExecutor(JudgePanel.build(POLICY), metrics=RedTeamMetrics(), concurrency=16)
    started = time.perf_counter()
    results = await executor.execute("perf", probes, agent)
    summary = summarize(results, resamples=2000, seed=3)
    elapsed = time.perf_counter() - started
    assert summary.total == 394
    assert elapsed < 10


async def test_judging_overhead_per_probe() -> None:
    probe = expand(SUITE, 1)[0]
    panel = JudgePanel.build(POLICY)
    response = TargetResponse(output="A handover summary without identifiers. " * 40)
    started = time.perf_counter()
    for _ in range(500):
        await panel.assess(probe, response)
    per_probe_ms = (time.perf_counter() - started) * 1000 / 500
    assert per_probe_ms < 5
