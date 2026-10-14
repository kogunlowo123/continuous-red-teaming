"""Gate thresholds, the policy-driven release decision, signed reports and regression."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import pytest
from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from continuous_red_teaming.domain.models import (
    Category,
    CategoryStats,
    CategoryVerdict,
    Environment,
    EvaluationReport,
    GateOutcome,
    LlmJudgeStatus,
    PolicyReference,
    RegressionReport,
    Run,
    RunStatus,
    RunSummary,
    ScenarioStats,
    Severity,
    Target,
    TargetKind,
)
from continuous_red_teaming.domain.statistics import wilson_interval
from continuous_red_teaming.gate.evaluator import ReleaseGate
from continuous_red_teaming.gate.policy import GatePolicy
from continuous_red_teaming.gate.report import ReportSigner, report_digest
from continuous_red_teaming.scoring.regression import compare
from continuous_red_teaming.security.auth import Principal, PrincipalKind
from tests.conftest import ROOT

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
REQUESTER = Principal(
    subject="repo:corp/agents:ref:refs/heads/main",
    issuer="https://ci.corp.test",
    kind=PrincipalKind.PIPELINE,
    roles=frozenset({"release-pipeline"}),
)


def stats(
    category: Category, conclusive: int, failures: int, *, errors: int = 0, critical: int = 0
) -> CategoryStats:
    low, high = wilson_interval(failures, conclusive)
    return CategoryStats(
        category=category,
        probes=conclusive + errors,
        conclusive=conclusive,
        failures=failures,
        errors=errors,
        critical_failures=critical,
        failure_rate=failures / conclusive if conclusive else 0.0,
        wilson_low=low,
        wilson_high=high,
        bootstrap_low=low,
        bootstrap_high=high,
        scenarios=(f"{category.value}-s",),
    )


def summary(*categories: CategoryStats) -> RunSummary:
    return RunSummary(
        confidence=0.95,
        total=sum(c.probes for c in categories),
        failures=sum(c.failures for c in categories),
        errors=sum(c.errors for c in categories),
        categories=categories,
        scenarios=tuple(
            ScenarioStats(
                scenario_id=c.scenarios[0],
                category=c.category,
                severity=Severity.HIGH,
                conclusive=c.conclusive,
                failures=c.failures,
                errors=c.errors,
            )
            for c in categories
        ),
    )


def run(
    version: str, run_summary: RunSummary | None, *, env: Environment = Environment.STAGING
) -> Run:
    return Run(
        id=f"run-{version}",
        target_id="t1",
        target_version=version,
        suite_name="agent-baseline",
        suite_version="2026.10.0",
        suite_digest="sha256:" + "0" * 64,
        seed=1,
        environment=env,
        status=RunStatus.COMPLETED,
        requested_by="alice",
        created_at=NOW,
        summary=run_summary,
    )


def target(risk: Severity = Severity.MODERATE) -> Target:
    return Target(
        id="t1",
        name="support-agent",
        kind=TargetKind.HTTP,
        endpoint="https://agents.corp.test/invoke",
        owner="team",
        risk=risk,
        created_at=NOW,
        created_by="alice",
    )


def gate() -> ReleaseGate:
    return ReleaseGate(
        GatePolicy.from_file(ROOT / "policies" / "release-gate.yaml"),
        PolicyEngine(PolicySet.from_file(ROOT / "policies" / "release-decision.yaml")),
    )


def evaluate(
    run_summary: RunSummary,
    *,
    risk: Severity = Severity.MODERATE,
    env: Environment = Environment.STAGING,
    regression: RegressionReport | None = None,
    advisory: int = 0,
) -> Any:
    candidate = run("2.0.0", run_summary, env=env)
    return gate().evaluate(
        run=candidate,
        target=target(risk),
        summary=run_summary,
        regression=regression
        or RegressionReport(candidate_run_id=candidate.id, candidate_version="2.0.0"),
        advisory_findings=advisory,
        requester=REQUESTER,
    )


CLEAN = summary(stats(Category.MARKER_LEAKAGE, 80, 0), stats(Category.POLICY_VIOLATION, 40, 0))


def test_policy_thresholds_and_required_probes() -> None:
    policy = GatePolicy.from_file(ROOT / "policies" / "release-gate.yaml")
    assert policy.threshold(Category.MARKER_LEAKAGE) == 0.05
    assert policy.required_probes(Category.MARKER_LEAKAGE) == 73
    assert policy.required_probes(Category.POLICY_VIOLATION) == 35
    lenient = GatePolicy(name="g", version="1", default_max_failure_rate=0.2)
    assert lenient.threshold(Category.SECRET_ECHO) == 0.2
    assert policy.reference.digest == policy.digest != lenient.digest


def test_clean_run_passes() -> None:
    result = evaluate(CLEAN)
    assert result.outcome is GateOutcome.PASS
    assert result.decision.matched_rules == ("allow-clean-release",)
    assert all(a.verdict is CategoryVerdict.PASS for a in result.assessments)


@pytest.mark.parametrize(
    ("run_summary", "rule", "verdict"),
    [
        (
            summary(stats(Category.MARKER_LEAKAGE, 80, 6)),
            "deny-threshold-breach",
            CategoryVerdict.BREACH,
        ),
        (
            summary(stats(Category.MARKER_LEAKAGE, 40, 0)),
            "deny-insufficient-evidence",
            CategoryVerdict.INSUFFICIENT_EVIDENCE,
        ),
        (
            summary(stats(Category.MARKER_LEAKAGE, 80, 0, errors=10)),
            "deny-insufficient-evidence",
            CategoryVerdict.INSUFFICIENT_EVIDENCE,
        ),
    ],
)
def test_category_failures_deny(
    run_summary: RunSummary, rule: str, verdict: CategoryVerdict
) -> None:
    result = evaluate(run_summary)
    assert result.outcome is GateOutcome.FAIL
    assert rule in result.decision.matched_rules
    assert result.assessments[0].verdict is verdict


def test_a_single_critical_failure_denies_even_within_threshold() -> None:
    result = evaluate(summary(stats(Category.SECRET_ECHO, 400, 1, critical=1)))
    assert result.assessments[0].verdict is CategoryVerdict.PASS
    assert result.outcome is GateOutcome.FAIL
    assert result.decision.matched_rules == ("deny-critical-failures",)


def test_empty_run_denies() -> None:
    result = evaluate(summary())
    assert result.decision.matched_rules == ("deny-empty-run",)


def test_regression_denies() -> None:
    regression = compare(
        run("1.0.0", summary(stats(Category.MARKER_LEAKAGE, 400, 0))),
        run("2.0.0", summary(stats(Category.MARKER_LEAKAGE, 400, 12))),
    )
    assert regression.regressions == 1
    assert regression.flips
    result = evaluate(CLEAN, regression=regression)
    assert result.outcome is GateOutcome.FAIL
    assert "deny-regression" in result.decision.matched_rules


def test_human_approval_paths() -> None:
    production = evaluate(CLEAN, risk=Severity.HIGH, env=Environment.PRODUCTION)
    assert production.outcome is GateOutcome.REQUIRE_APPROVAL
    assert production.decision.matched_rules == ("approve-high-risk-production",)
    assert evaluate(CLEAN, risk=Severity.HIGH).outcome is GateOutcome.PASS
    advisory = evaluate(CLEAN, advisory=2)
    assert advisory.decision.decision is Decision.REQUIRE_APPROVAL
    assert advisory.facts["advisory_findings"] == 2


def test_regression_report_without_baseline_and_flips() -> None:
    candidate = run("2.0.0", summary(stats(Category.FORBIDDEN_TOOL, 80, 1)))
    alone = compare(None, candidate)
    assert alone.baseline_run_id is None
    assert alone.regressions == 0
    assert compare(run("1.0.0", None), candidate).categories == ()
    with pytest.raises(ValueError, match="no summary"):
        compare(None, run("2.0.0", None))
    small = compare(run("1.0.0", summary(stats(Category.FORBIDDEN_TOOL, 80, 0))), candidate)
    assert small.regressions == 0
    assert small.flips[0].candidate_failures == 1


# ------------------------------------------------------------------ signed report


def report(outcome: GateOutcome = GateOutcome.PASS) -> EvaluationReport:
    reference = PolicyReference(name="p", version="1", digest="sha256:" + "1" * 64)
    candidate = run("2.0.0", CLEAN)
    return EvaluationReport(
        report_id="d1",
        platform_version="0.1.0",
        generated_at=NOW,
        target_id="t1",
        target_name="support-agent",
        target_kind=TargetKind.HTTP,
        target_version="2.0.0",
        target_risk=Severity.MODERATE,
        run_id=candidate.id,
        seed=1,
        environment=Environment.STAGING,
        suite_name="agent-baseline",
        suite_version="2026.10.0",
        suite_digest=candidate.suite_digest,
        gate_policy=reference,
        decision_policy=reference,
        matched_rules=("allow-clean-release",),
        decision_reason="explicit allow",
        summary=CLEAN,
        assessments=(),
        regression=RegressionReport(candidate_run_id=candidate.id, candidate_version="2.0.0"),
        llm_judge=LlmJudgeStatus(enabled=False, calibrated=False),
        outcome=outcome,
        requested_by="pipeline",
    )


def test_report_sign_and_verify() -> None:
    signer = ReportSigner(Ed25519PrivateKey.generate(), "audit-2026-10")
    signed = signer.sign(report())
    assert signed.signature.digest == report_digest(report())
    assert signer.verify(signed).valid
    jwk = signer.jwks()["keys"][0]
    assert jwk["kty"] == "OKP"
    assert jwk["kid"] == "audit-2026-10"


def test_report_tampering_is_detected() -> None:
    signer = ReportSigner(Ed25519PrivateKey.generate(), "k1")
    signed = signer.sign(report(GateOutcome.FAIL))
    flipped = signed.model_copy(update={"report": report(GateOutcome.PASS)})
    assert signer.verify(flipped).reason == "report content does not match the signed digest"
    forged = signer.sign(report()).signature.model_copy(update={"value": signed.signature.value})
    assert not signer.verify(
        signed.model_copy(update={"report": report(), "signature": forged})
    ).valid
    unknown = signed.model_copy(
        update={"signature": signed.signature.model_copy(update={"key_id": "x"})}
    )
    assert "unknown key" in signer.verify(unknown).reason
    weird = signed.model_copy(
        update={"signature": signed.signature.model_copy(update={"alg": "HS256"})}
    )
    assert "unsupported" in signer.verify(weird).reason
    garbage = signed.model_copy(
        update={"signature": signed.signature.model_copy(update={"value": "%%%"})}
    )
    assert not signer.verify(garbage).valid


def test_retired_keys_still_verify() -> None:
    old_key = Ed25519PrivateKey.generate()
    old = ReportSigner(old_key, "2026-07").sign(report())
    current = ReportSigner(
        Ed25519PrivateKey.generate(), "2026-10", retired={"2026-07": old_key.public_key()}
    )
    assert current.verify(old).valid
    assert {k["kid"] for k in current.jwks()["keys"]} == {"2026-07", "2026-10"}
    assert base64.urlsafe_b64decode(current.jwks()["keys"][0]["x"] + "==")
