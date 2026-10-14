"""Regression analysis between two runs of the same suite on different target versions.

A category regresses when the lower bound of the Newcombe confidence interval
for (candidate failure rate - baseline failure rate) is above zero: the
candidate is worse with the configured confidence, not just noisier. Scenario
flips (no failures before, failures now) are listed for triage even when they
are not statistically significant on their own.
"""

from __future__ import annotations

from continuous_red_teaming.domain.models import (
    RegressionFinding,
    RegressionReport,
    Run,
    RunSummary,
    ScenarioFlip,
)
from continuous_red_teaming.domain.statistics import newcombe_difference


def compare(baseline: Run | None, candidate: Run, *, confidence: float = 0.95) -> RegressionReport:
    if candidate.summary is None:
        raise ValueError("candidate run has no summary")
    if baseline is None or baseline.summary is None:
        return RegressionReport(
            candidate_run_id=candidate.id, candidate_version=candidate.target_version
        )
    return RegressionReport(
        baseline_run_id=baseline.id,
        baseline_version=baseline.target_version,
        candidate_run_id=candidate.id,
        candidate_version=candidate.target_version,
        categories=_categories(baseline.summary, candidate.summary, confidence),
        flips=_flips(baseline.summary, candidate.summary),
    )


def _categories(
    baseline: RunSummary, candidate: RunSummary, confidence: float
) -> tuple[RegressionFinding, ...]:
    findings: list[RegressionFinding] = []
    for current in candidate.categories:
        before = baseline.category(current.category)
        if before is None or before.conclusive == 0 or current.conclusive == 0:
            continue
        difference, low, high = newcombe_difference(
            before.failures, before.conclusive, current.failures, current.conclusive, confidence
        )
        findings.append(
            RegressionFinding(
                category=current.category,
                baseline_rate=before.failure_rate,
                candidate_rate=current.failure_rate,
                difference=difference,
                difference_low=low,
                difference_high=high,
                significant=low > 0.0,
            )
        )
    return tuple(findings)


def _flips(baseline: RunSummary, candidate: RunSummary) -> tuple[ScenarioFlip, ...]:
    flips: list[ScenarioFlip] = []
    for current in candidate.scenarios:
        before = baseline.scenario(current.scenario_id)
        if before is None or before.conclusive == 0:
            continue
        if before.failures == 0 and current.failures > 0:
            flips.append(
                ScenarioFlip(
                    scenario_id=current.scenario_id,
                    baseline_failures=before.failures,
                    baseline_conclusive=before.conclusive,
                    candidate_failures=current.failures,
                    candidate_conclusive=current.conclusive,
                )
            )
    return tuple(flips)
