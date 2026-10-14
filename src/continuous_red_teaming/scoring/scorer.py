"""Turns probe results into per-category and per-scenario statistics."""

from __future__ import annotations

import hashlib
import random
from collections import defaultdict
from collections.abc import Sequence

from continuous_red_teaming.domain.models import (
    CategoryStats,
    ProbeOutcome,
    ProbeResult,
    RunSummary,
    ScenarioStats,
    Severity,
)
from continuous_red_teaming.domain.statistics import cluster_bootstrap_interval, wilson_interval


def summarize(
    results: Sequence[ProbeResult],
    *,
    confidence: float = 0.95,
    resamples: int = 2000,
    seed: int = 0,
) -> RunSummary:
    by_scenario: dict[str, list[ProbeResult]] = defaultdict(list)
    for result in results:
        by_scenario[result.scenario_id].append(result)

    scenarios: list[ScenarioStats] = []
    for scenario_id in sorted(by_scenario):
        group = by_scenario[scenario_id]
        errors = sum(1 for r in group if r.outcome is ProbeOutcome.ERROR)
        scenarios.append(
            ScenarioStats(
                scenario_id=scenario_id,
                category=group[0].category,
                severity=group[0].severity,
                conclusive=len(group) - errors,
                failures=sum(1 for r in group if r.outcome is ProbeOutcome.FAIL),
                errors=errors,
            )
        )

    categories: list[CategoryStats] = []
    for category in sorted({s.category for s in scenarios}):
        members = [s for s in scenarios if s.category is category]
        conclusive = sum(s.conclusive for s in members)
        failures = sum(s.failures for s in members)
        errors = sum(s.errors for s in members)
        low, high = wilson_interval(failures, conclusive, confidence)
        rng_seed = hashlib.sha256(f"{seed}:{category.value}".encode()).digest()
        # Resampling, not cryptography: the interval must be reproducible from the seed.
        rng = random.Random(int.from_bytes(rng_seed[:8], "big"))  # noqa: S311  # nosec B311
        boot_low, boot_high = cluster_bootstrap_interval(
            [(s.failures, s.conclusive) for s in members],
            confidence=confidence,
            resamples=resamples,
            rng=rng,
        )
        categories.append(
            CategoryStats(
                category=category,
                probes=conclusive + errors,
                conclusive=conclusive,
                failures=failures,
                errors=errors,
                critical_failures=sum(
                    s.failures for s in members if s.severity is Severity.CRITICAL
                ),
                failure_rate=failures / conclusive if conclusive else 0.0,
                wilson_low=low,
                wilson_high=high,
                bootstrap_low=boot_low,
                bootstrap_high=boot_high,
                scenarios=tuple(s.scenario_id for s in members),
            )
        )
    return RunSummary(
        confidence=confidence,
        total=len(results),
        failures=sum(1 for r in results if r.outcome is ProbeOutcome.FAIL),
        errors=sum(1 for r in results if r.outcome is ProbeOutcome.ERROR),
        categories=tuple(categories),
        scenarios=tuple(scenarios),
    )
