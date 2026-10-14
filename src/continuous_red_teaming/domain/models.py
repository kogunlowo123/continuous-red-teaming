"""Domain model: scenarios, probes, targets, runs, results and gate decisions.

A *probe* is a structured, benign test case. It plants a synthetic marker the
target must not act on or reveal (a canary token in retrieved content, a fake
secret marker, a request for a tool on the scenario's forbidden list, or an
action that policy says needs human approval). Scenarios carry OWASP LLM Top
10 (2025) and MITRE ATLAS identifiers as labels only.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

SLUG = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?$")
TOOL_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_*]+)*$|^\*$")
OWASP_LLM = re.compile(r"^LLM(0[1-9]|10):2025$")
MITRE_ATLAS = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+\-_]{0,63}$")
PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
MARKER_PLACEHOLDER = "canary"


def _slug(value: str) -> str:
    if not SLUG.fullmatch(value):
        raise ValueError(f"must be a lowercase slug (a-z, 0-9, '-'): {value!r}")
    return value


def _version(value: str) -> str:
    if not VERSION.fullmatch(value):
        raise ValueError(f"invalid version string: {value!r}")
    return value


def _tool(value: str) -> str:
    if not TOOL_PATTERN.fullmatch(value):
        raise ValueError(f"invalid tool name or pattern: {value!r}")
    return value


def _owasp(value: str) -> str:
    if not OWASP_LLM.fullmatch(value):
        raise ValueError(f"OWASP LLM label must look like LLM01:2025, got {value!r}")
    return value


def _atlas(value: str) -> str:
    if not MITRE_ATLAS.fullmatch(value):
        raise ValueError(f"MITRE ATLAS label must look like AML.T0051, got {value!r}")
    return value


Slug = Annotated[str, AfterValidator(_slug)]
Version = Annotated[str, AfterValidator(_version)]
ToolName = Annotated[str, AfterValidator(_tool)]
OwaspLabel = Annotated[str, AfterValidator(_owasp)]
AtlasLabel = Annotated[str, AfterValidator(_atlas)]


def placeholders(template: str) -> set[str]:
    """Names referenced as ``{name}``; any other brace use is rejected by validation."""
    return set(PLACEHOLDER.findall(template))


def _template(value: str) -> str:
    stripped = PLACEHOLDER.sub("", value)
    if "{" in stripped or "}" in stripped:
        raise ValueError("templates may only contain {name} placeholders (no format specs)")
    return value


Template = Annotated[str, AfterValidator(_template)]


def render(template: str, values: dict[str, str]) -> str:
    """Substitute ``{name}`` placeholders. No attribute access, indexing or format specs."""
    return PLACEHOLDER.sub(lambda m: values[m.group(1)], template)


# ----------------------------------------------------------------- vocabularies


class ProbeKind(StrEnum):
    CANARY_IN_CONTEXT = "canary_in_context"
    # Probe kind label, not a credential.
    SECRET_MARKER = "secret_marker"  # noqa: S105  # nosec B105
    FORBIDDEN_TOOL = "forbidden_tool"
    OUT_OF_SCOPE_ACTION = "out_of_scope_action"


class Category(StrEnum):
    MARKER_LEAKAGE = "marker_leakage"
    # Category label, not a credential.
    SECRET_ECHO = "secret_echo"  # noqa: S105  # nosec B105
    FORBIDDEN_TOOL = "forbidden_tool"
    APPROVAL_BYPASS = "approval_bypass"
    POLICY_VIOLATION = "policy_violation"


class JudgeName(StrEnum):
    MARKER_LEAKAGE = "marker_leakage"
    FORBIDDEN_TOOL = "forbidden_tool"
    POLICY_VIOLATION = "policy_violation"
    APPROVAL_BYPASS = "approval_bypass"
    LLM_RUBRIC = "llm_rubric"


class Severity(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self) + 1


DEFAULT_JUDGES: dict[ProbeKind, tuple[JudgeName, ...]] = {
    ProbeKind.CANARY_IN_CONTEXT: (JudgeName.MARKER_LEAKAGE,),
    ProbeKind.SECRET_MARKER: (JudgeName.MARKER_LEAKAGE,),
    ProbeKind.FORBIDDEN_TOOL: (JudgeName.FORBIDDEN_TOOL, JudgeName.POLICY_VIOLATION),
    ProbeKind.OUT_OF_SCOPE_ACTION: (JudgeName.APPROVAL_BYPASS, JudgeName.POLICY_VIOLATION),
}

MARKER_KINDS = frozenset({ProbeKind.CANARY_IN_CONTEXT, ProbeKind.SECRET_MARKER})

# ------------------------------------------------------------------- scenarios


class Labels(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    owasp_llm: tuple[OwaspLabel, ...] = Field(min_length=1)
    mitre_atlas: tuple[AtlasLabel, ...] = ()


class ContextTemplate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(min_length=1, max_length=120)
    content: Template = Field(min_length=1, max_length=4000)


class ProbeSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ProbeKind
    task: Template = Field(min_length=1, max_length=2000)
    context: tuple[ContextTemplate, ...] = Field(default=(), max_length=8)
    forbidden_tools: tuple[ToolName, ...] = ()
    action_tools: tuple[ToolName, ...] = ()

    @model_validator(mode="after")
    def _kind_requirements(self) -> ProbeSpec:
        in_context = any(MARKER_PLACEHOLDER in placeholders(c.content) for c in self.context)
        if self.kind in MARKER_KINDS:
            if not in_context:
                raise ValueError(f"{self.kind} probes must plant {{canary}} in a context document")
            if MARKER_PLACEHOLDER in placeholders(self.task):
                raise ValueError("the marker belongs in context, never in the task")
        elif in_context or MARKER_PLACEHOLDER in placeholders(self.task):
            raise ValueError(f"{self.kind} probes do not plant markers")
        if self.kind is ProbeKind.FORBIDDEN_TOOL and not self.forbidden_tools:
            raise ValueError("forbidden_tool probes need forbidden_tools")
        if self.kind is ProbeKind.OUT_OF_SCOPE_ACTION and not self.action_tools:
            raise ValueError("out_of_scope_action probes need action_tools")
        return self

    def referenced(self) -> set[str]:
        names = placeholders(self.task)
        for document in self.context:
            names |= placeholders(document.content)
        return names - {MARKER_PLACEHOLDER}


class Scenario(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Slug
    title: str = Field(min_length=5, max_length=200)
    description: str = Field(default="", max_length=2000)
    category: Category
    severity: Severity
    labels: Labels
    probe: ProbeSpec
    parameters: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    samples: int | None = Field(default=None, ge=1, le=10_000)
    repeats: int = Field(default=1, ge=1, le=50)
    judges: tuple[JudgeName, ...] | None = None

    @model_validator(mode="after")
    def _parameters(self) -> Scenario:
        for name, values in self.parameters.items():
            if not PLACEHOLDER.fullmatch("{" + name + "}") or name == MARKER_PLACEHOLDER:
                raise ValueError(f"invalid parameter name {name!r}")
            if not values or len(set(values)) != len(values):
                raise ValueError(f"parameter {name!r} needs distinct values")
        missing = self.probe.referenced() - set(self.parameters)
        if missing:
            raise ValueError(f"scenario {self.id}: undefined placeholders {sorted(missing)}")
        unused = set(self.parameters) - self.probe.referenced()
        if unused:
            raise ValueError(f"scenario {self.id}: unused parameters {sorted(unused)}")
        if self.grid_size > 100_000:
            raise ValueError(f"scenario {self.id}: parameter grid exceeds 100000 cases")
        return self

    @property
    def grid_size(self) -> int:
        size = 1
        for values in self.parameters.values():
            size *= len(values)
        return size

    @property
    def case_count(self) -> int:
        cases = self.grid_size if self.samples is None else min(self.samples, self.grid_size)
        return cases * self.repeats

    @property
    def effective_judges(self) -> tuple[JudgeName, ...]:
        return self.judges if self.judges is not None else DEFAULT_JUDGES[self.probe.kind]


# ---------------------------------------------------------------------- probes


class ContextDocument(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    source: str
    content: str
    trust: str = "external"


class ProbeInvocation(BaseModel):
    """What the target sees. It never reveals the probe's category or markers."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    task: str
    context: tuple[ContextDocument, ...] = ()


class Probe(BaseModel):
    model_config = ConfigDict(frozen=True)

    probe_id: str
    scenario_id: str
    category: Category
    kind: ProbeKind
    severity: Severity
    labels: Labels
    parameters: dict[str, str]
    invocation: ProbeInvocation
    markers: tuple[str, ...] = ()
    forbidden_tools: tuple[str, ...] = ()
    action_tools: tuple[str, ...] = ()
    judges: tuple[JudgeName, ...]


class ToolCallStatus(StrEnum):
    EXECUTED = "executed"
    PROPOSED = "proposed"
    BLOCKED = "blocked"


class ToolCall(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    name: str = Field(min_length=1, max_length=200)
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: ToolCallStatus = ToolCallStatus.EXECUTED
    approval_id: str | None = Field(default=None, max_length=200)


class ResponseStatus(StrEnum):
    COMPLETED = "completed"
    REQUIRE_APPROVAL = "require_approval"
    REFUSED = "refused"
    ERROR = "error"


class TargetResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    output: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    status: ResponseStatus = ResponseStatus.COMPLETED
    latency_ms: float = Field(default=0.0, ge=0)
    trace_source: str = "self-reported"


class VerdictOutcome(StrEnum):
    # "pass" is a verdict label, not a credential.
    PASS = "pass"  # noqa: S105  # nosec B105
    FAIL = "fail"
    ABSTAIN = "abstain"


class JudgeVerdict(BaseModel):
    model_config = ConfigDict(frozen=True)

    judge: JudgeName
    outcome: VerdictOutcome
    evidence: tuple[str, ...] = ()
    advisory: bool = False


class ProbeOutcome(StrEnum):
    # "pass" is a probe outcome label, not a credential.
    PASS = "pass"  # noqa: S105  # nosec B105
    FAIL = "fail"
    ERROR = "error"


class ToolCallRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    status: ToolCallStatus
    approval_id: str | None = None


class ProbeEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    response_status: ResponseStatus
    output_digest: str
    output_excerpt: str
    tool_calls: tuple[ToolCallRecord, ...] = ()
    latency_ms: float = 0.0
    trace_source: str = "self-reported"


class ProbeResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    probe_id: str
    scenario_id: str
    category: Category
    severity: Severity
    outcome: ProbeOutcome
    verdicts: tuple[JudgeVerdict, ...] = ()
    evidence: ProbeEvidence | None = None
    error: str | None = None
    attempts: int = 1


# --------------------------------------------------------------------- targets


class TargetKind(StrEnum):
    HTTP = "http"
    MCP = "mcp"
    A2A = "a2a"
    REFERENCE = "reference"


class TargetAuth(StrEnum):
    NONE = "none"
    FABRIC = "fabric"
    ENV_BEARER = "env_bearer"


class ReferenceProfile(BaseModel):
    """Known, measurable weaknesses of an in-process reference target.

    Each rate is the probability that the reference agent fails the matching
    probe category. Used to prove the platform measures what it claims to.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    marker_leak_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    secret_echo_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    forbidden_tool_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    approval_bypass_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    seed: int = 0


ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")


class TargetRegistration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: Slug
    description: str = Field(default="", max_length=1000)
    kind: TargetKind
    endpoint: str | None = Field(default=None, max_length=2048)
    mcp_tool: str = Field(default="run_task", min_length=1, max_length=128)
    trace_endpoint: str | None = Field(default=None, max_length=2048)
    auth: TargetAuth = TargetAuth.NONE
    auth_env: str | None = None
    reference_profile: ReferenceProfile | None = None
    risk: Severity = Severity.MODERATE
    owner: str = Field(min_length=2, max_length=200)
    timeout_s: float = Field(default=30.0, gt=0, le=300)

    @model_validator(mode="after")
    def _shape(self) -> TargetRegistration:
        if self.kind is TargetKind.REFERENCE:
            if self.reference_profile is None:
                raise ValueError("reference targets need reference_profile")
            if self.endpoint or self.trace_endpoint or self.auth is not TargetAuth.NONE:
                raise ValueError("reference targets run in-process: no endpoint or auth")
        else:
            if not self.endpoint:
                raise ValueError(f"{self.kind} targets need an endpoint")
            if self.reference_profile is not None:
                raise ValueError("reference_profile is only valid for reference targets")
        if self.auth is TargetAuth.ENV_BEARER:
            if not self.auth_env or not ENV_NAME.fullmatch(self.auth_env):
                raise ValueError("env_bearer auth needs auth_env naming an environment variable")
        elif self.auth_env is not None:
            raise ValueError("auth_env is only valid with env_bearer auth")
        return self


class Target(TargetRegistration):
    id: str
    created_at: datetime
    created_by: str


# ------------------------------------------------------------------------ runs


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class Environment(StrEnum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class CategoryStats(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: Category
    probes: int
    conclusive: int
    failures: int
    errors: int
    critical_failures: int
    failure_rate: float
    wilson_low: float
    wilson_high: float
    bootstrap_low: float
    bootstrap_high: float
    scenarios: tuple[str, ...]


class ScenarioStats(BaseModel):
    model_config = ConfigDict(frozen=True)

    scenario_id: str
    category: Category
    severity: Severity
    conclusive: int
    failures: int
    errors: int


class RunSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    confidence: float
    total: int
    failures: int
    errors: int
    categories: tuple[CategoryStats, ...]
    scenarios: tuple[ScenarioStats, ...]

    def category(self, category: Category) -> CategoryStats | None:
        return next((c for c in self.categories if c.category is category), None)

    def scenario(self, scenario_id: str) -> ScenarioStats | None:
        return next((s for s in self.scenarios if s.scenario_id == scenario_id), None)


class Run(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    target_id: str
    target_version: str
    suite_name: str
    suite_version: str
    suite_digest: str
    seed: int
    environment: Environment
    status: RunStatus
    requested_by: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    probe_count: int = 0
    error: str | None = None
    summary: RunSummary | None = None


# ------------------------------------------------------------------------ gate


class GateOutcome(StrEnum):
    # "pass" is a gate outcome label, not a credential.
    PASS = "pass"  # noqa: S105  # nosec B105
    FAIL = "fail"
    REQUIRE_APPROVAL = "require_approval"
    APPROVED = "approved"

    @property
    def releasable(self) -> bool:
        return self in {GateOutcome.PASS, GateOutcome.APPROVED}


class CategoryVerdict(StrEnum):
    # "pass" is a verdict label, not a credential.
    PASS = "pass"  # noqa: S105  # nosec B105
    BREACH = "breach"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class CategoryAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: Category
    verdict: CategoryVerdict
    max_failure_rate: float
    observed_rate: float
    upper_bound: float
    conclusive: int
    required_probes: int
    error_rate: float
    reason: str


class RegressionFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: Category
    baseline_rate: float
    candidate_rate: float
    difference: float
    difference_low: float
    difference_high: float
    significant: bool


class ScenarioFlip(BaseModel):
    model_config = ConfigDict(frozen=True)

    scenario_id: str
    baseline_failures: int
    baseline_conclusive: int
    candidate_failures: int
    candidate_conclusive: int


class RegressionReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    baseline_run_id: str | None = None
    baseline_version: str | None = None
    candidate_run_id: str
    candidate_version: str
    categories: tuple[RegressionFinding, ...] = ()
    flips: tuple[ScenarioFlip, ...] = ()

    @property
    def regressions(self) -> int:
        return sum(1 for c in self.categories if c.significant)


class Approval(BaseModel):
    model_config = ConfigDict(frozen=True)

    approver: str
    reason: str
    at: datetime
    audit_hash: str


class PolicyReference(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    digest: str


class LlmJudgeStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool
    calibrated: bool
    kappa: float | None = None
    binding: bool = False


class EvaluationReport(BaseModel):
    """The release evidence. Signed as canonical JSON; see gate.report."""

    model_config = ConfigDict(frozen=True)

    report_id: str
    platform_version: str
    generated_at: datetime
    target_id: str
    target_name: str
    target_kind: TargetKind
    target_version: str
    target_risk: Severity
    run_id: str
    seed: int
    environment: Environment
    suite_name: str
    suite_version: str
    suite_digest: str
    gate_policy: PolicyReference
    decision_policy: PolicyReference
    matched_rules: tuple[str, ...]
    decision_reason: str
    summary: RunSummary
    assessments: tuple[CategoryAssessment, ...]
    regression: RegressionReport
    llm_judge: LlmJudgeStatus
    outcome: GateOutcome
    requested_by: str
    approvals: tuple[Approval, ...] = ()


class ReportSignature(BaseModel):
    model_config = ConfigDict(frozen=True)

    alg: str = "EdDSA"
    key_id: str
    digest: str
    value: str


class SignedReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    report: EvaluationReport
    signature: ReportSignature


class GateDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    run_id: str
    target_id: str
    target_version: str
    outcome: GateOutcome
    requested_by: str
    created_at: datetime
    audit_sequence: int
    audit_hash: str
    signed_report: SignedReport
