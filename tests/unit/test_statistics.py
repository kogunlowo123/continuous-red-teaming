"""Interval estimators against closed-form values and invariants."""

from __future__ import annotations

import math
import random

import pytest
from hypothesis import given
from hypothesis import strategies as st

from continuous_red_teaming.domain.statistics import (
    cluster_bootstrap_interval,
    cohens_kappa,
    newcombe_difference,
    wilson_interval,
    z_value,
    zero_failure_sample_size,
)


def test_z_value_matches_normal_quantiles() -> None:
    assert z_value(0.95) == pytest.approx(1.959964, abs=1e-6)
    assert z_value(0.99) == pytest.approx(2.575829, abs=1e-6)
    with pytest.raises(ValueError, match="confidence"):
        z_value(1.0)


def test_wilson_zero_failures_has_closed_form_upper_bound() -> None:
    low, high = wilson_interval(0, 10)
    z2 = z_value(0.95) ** 2
    assert low == 0.0
    assert high == pytest.approx(z2 / (10 + z2), rel=1e-9)


def test_wilson_symmetric_around_half() -> None:
    low, high = wilson_interval(5, 10)
    assert low == pytest.approx(0.2366, abs=1e-4)
    assert high == pytest.approx(0.7634, abs=1e-4)
    assert low + high == pytest.approx(1.0)


def test_wilson_all_failures_and_empty() -> None:
    assert wilson_interval(10, 10)[1] == 1.0
    assert wilson_interval(0, 0) == (0.0, 1.0)
    with pytest.raises(ValueError, match="failures"):
        wilson_interval(3, 2)


@given(n=st.integers(min_value=1, max_value=5000), data=st.data())
def test_wilson_contains_point_estimate(n: int, data: st.DataObject) -> None:
    failures = data.draw(st.integers(min_value=0, max_value=n))
    low, high = wilson_interval(failures, n)
    assert 0.0 <= low <= failures / n <= high <= 1.0


def test_zero_failure_sample_sizes() -> None:
    assert zero_failure_sample_size(0.05) == 73
    assert zero_failure_sample_size(0.10) == 35
    assert zero_failure_sample_size(0.01) == 381
    for rate in (0.2, 0.05, 0.02):
        n = zero_failure_sample_size(rate)
        assert wilson_interval(0, n)[1] <= rate < wilson_interval(0, n - 1)[1]
    with pytest.raises(ValueError, match="max_failure_rate"):
        zero_failure_sample_size(0.0)


def test_newcombe_contains_difference_and_is_antisymmetric() -> None:
    d, low, high = newcombe_difference(48, 80, 56, 70)
    assert low < d < high
    assert d == pytest.approx(56 / 70 - 48 / 80)
    d2, low2, high2 = newcombe_difference(56, 70, 48, 80)
    assert d2 == pytest.approx(-d)
    assert low2 == pytest.approx(-high)
    assert high2 == pytest.approx(-low)


def test_newcombe_detects_clear_regression_only() -> None:
    _, low, _ = newcombe_difference(0, 100, 20, 100)
    assert low > 0
    _, low_same, high_same = newcombe_difference(5, 100, 5, 100)
    assert low_same < 0 < high_same
    assert newcombe_difference(0, 0, 1, 10) == (0.0, -1.0, 1.0)


def test_cluster_bootstrap_is_seeded_and_bounded() -> None:
    clusters = [(0, 20), (3, 20), (1, 20), (6, 20), (0, 20)]
    first = cluster_bootstrap_interval(clusters, rng=random.Random(1))
    again = cluster_bootstrap_interval(clusters, rng=random.Random(1))
    assert first == again
    pooled = 10 / 100
    assert first[0] <= pooled <= first[1]
    assert cluster_bootstrap_interval([(0, 0)], rng=random.Random(1)) == (0.0, 1.0)
    with pytest.raises(ValueError, match="resamples"):
        cluster_bootstrap_interval(clusters, resamples=10, rng=random.Random(1))


def test_cluster_bootstrap_is_wider_than_wilson_for_heterogeneous_scenarios() -> None:
    clusters = [(0, 50), (0, 50), (15, 50), (0, 50)]
    low, high = cluster_bootstrap_interval(clusters, rng=random.Random(3))
    w_low, w_high = wilson_interval(15, 200)
    assert high - low > w_high - w_low


def test_cohens_kappa() -> None:
    perfect = [(True, True), (False, False), (True, True), (False, False)]
    assert cohens_kappa(perfect) == 1.0
    chance = [(True, True), (True, False), (False, True), (False, False)]
    assert cohens_kappa(chance) == pytest.approx(0.0)
    assert cohens_kappa([(True, True), (True, True)]) == 1.0
    assert cohens_kappa([(True, False), (True, False)]) == 0.0
    assert math.isclose(cohens_kappa([(True, False), (False, True)]), -1.0)
    with pytest.raises(ValueError, match="at least one"):
        cohens_kappa([])
