"""Request and response bodies of the HTTP API that are not domain models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from continuous_red_teaming.application.service import VersionPoint
from continuous_red_teaming.domain.models import (
    Category,
    GateDecision,
    Labels,
    Probe,
    ProbeKind,
    ProbeResult,
    Run,
    Severity,
    Target,
)
from continuous_red_teaming.domain.suites import Suite


class ScenarioView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    category: Category
    severity: Severity
    kind: ProbeKind
    labels: Labels
    probes: int


class SuiteView(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    digest: str
    description: str
    probe_count: int
    categories: tuple[Category, ...]
    scenarios: tuple[ScenarioView, ...]

    @classmethod
    def of(cls, suite: Suite) -> SuiteView:
        return cls(
            name=suite.name,
            version=suite.version,
            digest=suite.digest,
            description=suite.description,
            probe_count=suite.probe_count,
            categories=suite.categories,
            scenarios=tuple(
                ScenarioView(
                    id=s.id,
                    title=s.title,
                    category=s.category,
                    severity=s.severity,
                    kind=s.probe.kind,
                    labels=s.labels,
                    probes=s.case_count,
                )
                for s in suite.scenarios
            ),
        )


class SuiteList(BaseModel):
    items: list[SuiteView]


class Expansion(BaseModel):
    suite: str
    version: str
    digest: str
    seed: int
    probe_count: int
    probes: list[Probe]


class TargetList(BaseModel):
    items: list[Target]
    limit: int
    offset: int


class RunList(BaseModel):
    items: list[Run]
    limit: int
    offset: int


class ProbeResultList(BaseModel):
    items: list[ProbeResult]
    limit: int
    offset: int


class DecisionList(BaseModel):
    items: list[GateDecision]
    limit: int
    offset: int


class History(BaseModel):
    target_id: str
    points: list[VersionPoint]


class ApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=5, max_length=500)


class CalibrateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suite: str = Field(min_length=1, max_length=140)
    seed: int = Field(default=0, ge=0, le=2**31 - 1)
    examples: int = Field(default=100, ge=10, le=1000)


class SampleSize(BaseModel):
    max_failure_rate: float
    confidence: float
    zero_failure_probes: int


class OAuthError(BaseModel):
    error: str
    error_description: str
