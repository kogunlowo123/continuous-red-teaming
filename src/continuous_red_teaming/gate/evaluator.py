"""Release decision: statistical thresholds feed the agentic-core PolicyEngine.

The thresholds turn a run into facts (breached categories, insufficient
evidence, critical failures, regressions, advisory findings, target risk,
environment). The decision policy (``policies/release-decision.yaml``) turns
those facts into allow / deny / require_approval with deny-overrides and
default deny, and its digest is recorded in the signed report.
"""

from __future__ import annotations

from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicyDecision, PolicyEngine, PolicyRequest, Resource, Subject
from pydantic import BaseModel, ConfigDict

from continuous_red_teaming.domain.models import (
    CategoryAssessment,
    CategoryVerdict,
    GateOutcome,
    PolicyReference,
    RegressionReport,
    Run,
    RunSummary,
    Target,
)
from continuous_red_teaming.gate.policy import GatePolicy
from continuous_red_teaming.security.auth import Principal

OUTCOMES = {
    Decision.ALLOW: GateOutcome.PASS,
    Decision.DENY: GateOutcome.FAIL,
    Decision.REQUIRE_APPROVAL: GateOutcome.REQUIRE_APPROVAL,
}


class GateEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True)

    assessments: tuple[CategoryAssessment, ...]
    decision: PolicyDecision
    outcome: GateOutcome
    facts: dict[str, int]


class ReleaseGate:
    def __init__(self, thresholds: GatePolicy, decision_policy: PolicyEngine) -> None:
        self._thresholds = thresholds
        self._decisions = decision_policy

    @property
    def thresholds(self) -> GatePolicy:
        return self._thresholds

    @property
    def decision_policy(self) -> PolicyReference:
        policy = self._decisions.policy
        return PolicyReference(name=policy.name, version=policy.version, digest=policy.digest)

    def assess(self, summary: RunSummary) -> tuple[CategoryAssessment, ...]:
        assessments: list[CategoryAssessment] = []
        for stats in summary.categories:
            threshold = self._thresholds.threshold(stats.category)
            required = self._thresholds.required_probes(stats.category)
            error_rate = stats.errors / stats.probes if stats.probes else 1.0
            if stats.conclusive < required:
                verdict = CategoryVerdict.INSUFFICIENT_EVIDENCE
                reason = f"{stats.conclusive} conclusive probes, {required} required"
            elif error_rate > self._thresholds.max_error_rate:
                verdict = CategoryVerdict.INSUFFICIENT_EVIDENCE
                reason = (
                    f"target error rate {error_rate:.3f} exceeds "
                    f"{self._thresholds.max_error_rate:.3f}"
                )
            elif stats.wilson_high > threshold:
                verdict = CategoryVerdict.BREACH
                reason = (
                    f"upper bound {stats.wilson_high:.4f} at {summary.confidence:.0%} "
                    f"exceeds {threshold:.4f}"
                )
            else:
                verdict = CategoryVerdict.PASS
                reason = f"upper bound {stats.wilson_high:.4f} within {threshold:.4f}"
            assessments.append(
                CategoryAssessment(
                    category=stats.category,
                    verdict=verdict,
                    max_failure_rate=threshold,
                    observed_rate=stats.failure_rate,
                    upper_bound=stats.wilson_high,
                    conclusive=stats.conclusive,
                    required_probes=required,
                    error_rate=error_rate,
                    reason=reason,
                )
            )
        return tuple(assessments)

    def evaluate(
        self,
        *,
        run: Run,
        target: Target,
        summary: RunSummary,
        regression: RegressionReport,
        advisory_findings: int,
        requester: Principal,
    ) -> GateEvaluation:
        assessments = self.assess(summary)
        facts = {
            "breached_categories": sum(
                1 for a in assessments if a.verdict is CategoryVerdict.BREACH
            ),
            "insufficient_categories": sum(
                1 for a in assessments if a.verdict is CategoryVerdict.INSUFFICIENT_EVIDENCE
            ),
            "critical_failures": sum(c.critical_failures for c in summary.categories),
            "regressions": regression.regressions,
            "advisory_findings": advisory_findings,
            "target_risk": target.risk.rank,
            "categories": len(assessments),
        }
        decision = self._decisions.evaluate(
            PolicyRequest(
                subject=Subject(
                    id=requester.subject, kind=requester.kind.value, roles=requester.roles
                ),
                action="release:promote",
                resource=Resource(
                    type="agent-release",
                    id=f"{target.name}@{run.target_version}",
                    attributes=dict(facts),
                ),
                environment={"environment": run.environment.value},
            )
        )
        return GateEvaluation(
            assessments=assessments,
            decision=decision,
            outcome=OUTCOMES[decision.decision],
            facts=facts,
        )
