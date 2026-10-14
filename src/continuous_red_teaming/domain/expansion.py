"""Deterministic scenario expansion.

Given a suite and a run seed, expansion always produces the same probes in
the same order with the same markers, so a failing probe can be replayed
exactly and two target versions can be compared probe for probe.

* The parameter grid is the Cartesian product of parameter values in sorted
  key order.
* When ``samples`` is smaller than the grid, cases are drawn without
  replacement by a PRNG seeded from (suite digest, scenario id, run seed).
* Markers are ``CANARY-<uuid>`` values derived with HMAC-SHA256 from the run
  seed and probe id: reproducible for whoever holds the seed, unguessable for
  the target.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import random
import uuid
from collections.abc import Iterator

from continuous_red_teaming.domain.models import (
    MARKER_KINDS,
    MARKER_PLACEHOLDER,
    ContextDocument,
    Probe,
    ProbeInvocation,
    Scenario,
    render,
)
from continuous_red_teaming.domain.suites import Suite

MARKER_PREFIX = "CANARY-"


def _derive(seed: int, suite_digest: str, label: str) -> bytes:
    key = hashlib.sha256(f"{seed}:{suite_digest}".encode()).digest()
    return hmac.new(key, label.encode(), hashlib.sha256).digest()


def derive_uuid(seed: int, suite_digest: str, label: str) -> str:
    return str(uuid.UUID(bytes=_derive(seed, suite_digest, label)[:16], version=4))


def marker_for(seed: int, suite_digest: str, probe_id: str) -> str:
    return MARKER_PREFIX + derive_uuid(seed, suite_digest, f"marker:{probe_id}")


def scenario_rng(seed: int, suite_digest: str, scenario_id: str) -> random.Random:
    material = _derive(seed, suite_digest, f"sample:{scenario_id}")
    # Sampling, not cryptography: reproducibility is the requirement here.
    return random.Random(int.from_bytes(material[:8], "big"))  # noqa: S311  # nosec B311


def grid(scenario: Scenario) -> list[dict[str, str]]:
    names = sorted(scenario.parameters)
    if not names:
        return [{}]
    return [
        dict(zip(names, combo, strict=True))
        for combo in itertools.product(*(scenario.parameters[n] for n in names))
    ]


def select_cases(scenario: Scenario, seed: int, suite_digest: str) -> list[dict[str, str]]:
    cases = grid(scenario)
    if scenario.samples is None or scenario.samples >= len(cases):
        return cases
    rng = scenario_rng(seed, suite_digest, scenario.id)
    chosen = sorted(rng.sample(range(len(cases)), scenario.samples))
    return [cases[i] for i in chosen]


def expand_scenario(scenario: Scenario, seed: int, suite_digest: str) -> Iterator[Probe]:
    spec = scenario.probe
    for case_index, params in enumerate(select_cases(scenario, seed, suite_digest)):
        for repeat in range(scenario.repeats):
            probe_id = f"{scenario.id}:{case_index:04d}:{repeat:02d}"
            values = dict(params)
            markers: tuple[str, ...] = ()
            if spec.kind in MARKER_KINDS:
                marker = marker_for(seed, suite_digest, probe_id)
                values[MARKER_PLACEHOLDER] = marker
                markers = (marker,)
            context = tuple(
                ContextDocument(
                    id=f"doc-{index}",
                    source=document.source,
                    content=render(document.content, values),
                )
                for index, document in enumerate(spec.context)
            )
            yield Probe(
                probe_id=probe_id,
                scenario_id=scenario.id,
                category=scenario.category,
                kind=spec.kind,
                severity=scenario.severity,
                labels=scenario.labels,
                parameters=params,
                invocation=ProbeInvocation(
                    session_id=derive_uuid(seed, suite_digest, f"session:{probe_id}"),
                    task=render(spec.task, values),
                    context=context,
                ),
                markers=markers,
                forbidden_tools=spec.forbidden_tools,
                action_tools=spec.action_tools,
                judges=scenario.effective_judges,
            )


def expand(suite: Suite, seed: int) -> list[Probe]:
    digest = suite.digest
    return [probe for s in suite.scenarios for probe in expand_scenario(s, seed, digest)]
