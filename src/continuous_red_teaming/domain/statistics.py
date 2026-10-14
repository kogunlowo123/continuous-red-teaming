"""Interval estimates for probe failure rates.

* Wilson score interval: binomial proportion CI that behaves well at the
  extremes (zero failures, small n), unlike the Wald interval. The gate
  compares the Wilson *upper* bound to each category threshold, so a release
  passes only when we are confident the true failure rate is below it.
* Cluster bootstrap: probes expanded from one scenario share a template and
  are correlated, so the bootstrap resamples whole scenarios. It is reported
  next to Wilson as a dependence-aware sensitivity check.
* Newcombe hybrid score interval (method 10) for the difference between two
  independent proportions: used for regression detection across versions.
* Cohen's kappa: agreement between an LLM judge and the deterministic judges.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from statistics import NormalDist


def z_value(confidence: float) -> float:
    if not 0.5 < confidence < 1.0:
        raise ValueError("confidence must be in (0.5, 1.0)")
    return NormalDist().inv_cdf(1.0 - (1.0 - confidence) / 2.0)


def wilson_interval(failures: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    if n < 0 or failures < 0 or failures > n:
        raise ValueError("require 0 <= failures <= n")
    if n == 0:
        return 0.0, 1.0
    z = z_value(confidence)
    p = failures / n
    z2 = z * z
    denominator = 1.0 + z2 / n
    centre = (p + z2 / (2.0 * n)) / denominator
    half = (z / denominator) * math.sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n))
    low = 0.0 if failures == 0 else max(0.0, centre - half)
    high = 1.0 if failures == n else min(1.0, centre + half)
    return low, high


def cluster_bootstrap_interval(
    clusters: Sequence[tuple[int, int]],
    *,
    confidence: float = 0.95,
    resamples: int = 2000,
    rng: random.Random,
) -> tuple[float, float]:
    """Percentile CI of the pooled failure rate, resampling (failures, n) clusters."""
    populated = [(f, n) for f, n in clusters if n > 0]
    if not populated:
        return 0.0, 1.0
    if resamples < 100:
        raise ValueError("use at least 100 bootstrap resamples")
    k = len(populated)
    rates: list[float] = []
    for _ in range(resamples):
        failures = total = 0
        for _ in range(k):
            f, n = populated[rng.randrange(k)]
            failures += f
            total += n
        rates.append(failures / total)
    rates.sort()
    alpha = (1.0 - confidence) / 2.0
    low_index = max(0, math.floor(alpha * resamples))
    high_index = min(resamples - 1, math.ceil((1.0 - alpha) * resamples) - 1)
    return rates[low_index], rates[high_index]


def newcombe_difference(
    baseline_failures: int,
    baseline_n: int,
    candidate_failures: int,
    candidate_n: int,
    confidence: float = 0.95,
) -> tuple[float, float, float]:
    """CI for candidate rate minus baseline rate. Returns (difference, low, high)."""
    if baseline_n == 0 or candidate_n == 0:
        return 0.0, -1.0, 1.0
    p1 = baseline_failures / baseline_n
    p2 = candidate_failures / candidate_n
    l1, u1 = wilson_interval(baseline_failures, baseline_n, confidence)
    l2, u2 = wilson_interval(candidate_failures, candidate_n, confidence)
    difference = p2 - p1
    low = difference - math.sqrt((p2 - l2) ** 2 + (u1 - p1) ** 2)
    high = difference + math.sqrt((u2 - p2) ** 2 + (p1 - l1) ** 2)
    return difference, max(-1.0, low), min(1.0, high)


def zero_failure_sample_size(max_failure_rate: float, confidence: float = 0.95) -> int:
    """Smallest n for which 0 failures in n probes has a Wilson upper bound <= the rate."""
    if not 0.0 < max_failure_rate < 1.0:
        raise ValueError("max_failure_rate must be in (0, 1)")
    z2 = z_value(confidence) ** 2
    n = math.ceil(z2 * (1.0 - max_failure_rate) / max_failure_rate - 1e-9)
    while wilson_interval(0, n, confidence)[1] > max_failure_rate:
        n += 1
    return n


def cohens_kappa(pairs: Sequence[tuple[bool, bool]]) -> float:
    """Agreement between two binary raters beyond chance. 1 = perfect, 0 = chance."""
    n = len(pairs)
    if n == 0:
        raise ValueError("kappa needs at least one rated pair")
    observed = sum(1 for a, b in pairs if a == b) / n
    a_true = sum(1 for a, _ in pairs if a) / n
    b_true = sum(1 for _, b in pairs if b) / n
    expected = a_true * b_true + (1 - a_true) * (1 - b_true)
    if math.isclose(expected, 1.0):
        return 1.0 if math.isclose(observed, 1.0) else 0.0
    return (observed - expected) / (1.0 - expected)
