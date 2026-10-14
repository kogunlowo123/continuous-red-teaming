"""Red-team validation use cases.

Flow: Scenario Suite -> Probe Execution -> Evaluation -> Scoring -> Release Gate.

Every state change (target registration, run start and finish, gate
decision, approval, judge calibration) is recorded in the agentic-core signed
audit chain before the caller sees a result; if the audit write fails, the
operation fails.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Sequence
from datetime import datetime

from agentic_core.audit import AuditLog
from agentic_core.domain.identifiers import new_id
from agentic_core.observability import get_logger
from agentic_core.policy import PolicyEngine
from pydantic import BaseModel, ConfigDict, Field

from continuous_red_teaming import __version__
from continuous_red_teaming.adapters.factory import AdapterFactory
from continuous_red_teaming.adapters.reference import ReferenceAgent
from continuous_red_teaming.application.executor import ProbeExecutor
from continuous_red_teaming.domain.errors import (
    CapacityError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
)
from continuous_red_teaming.domain.expansion import expand
from continuous_red_teaming.domain.models import (
    Approval,
    Environment,
    EvaluationReport,
    GateDecision,
    GateOutcome,
    JudgeVerdict,
    LlmJudgeStatus,
    Probe,
    ProbeOutcome,
    ProbeResult,
    ReferenceProfile,
    RegressionReport,
    Run,
    RunStatus,
    SignedReport,
    Target,
    TargetRegistration,
    VerdictOutcome,
    Version,
)
from continuous_red_teaming.domain.ports import (
    Clock,
    DecisionRepository,
    RunRepository,
    TargetRepository,
)
from continuous_red_teaming.domain.suites import Suite, SuiteCatalog
from continuous_red_teaming.gate.evaluator import ReleaseGate
from continuous_red_teaming.gate.report import ReportSigner, Verification
from continuous_red_teaming.judges.llm import (
    CalibrationResult,
    LabelledExample,
    LlmRubricJudge,
    calibrate,
)
from continuous_red_teaming.judges.panel import JudgePanel
from continuous_red_teaming.observability.metrics import RedTeamMetrics
from continuous_red_teaming.scoring.regression import compare
from continuous_red_teaming.scoring.scorer import summarize
from continuous_red_teaming.security.auth import Principal

PLATFORM_ACTOR = "continuous-red-teaming"
log = get_logger("continuous_red_teaming.service")
RESULT_BATCH = 500


class RunRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    target_id: str = Field(min_length=1, max_length=64)
    target_version: Version
    suite: str = Field(min_length=1, max_length=140, description="name or name@version")
    seed: int | None = Field(default=None, ge=0, le=2**31 - 1)
    environment: Environment = Environment.STAGING


class VersionPoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    target_version: str
    run_id: str
    decision_id: str
    outcome: GateOutcome
    decided_at: datetime
    suite: str
    failure_upper_bounds: dict[str, float]


class RedTeamService:
    def __init__(
        self,
        *,
        suites: SuiteCatalog,
        targets: TargetRepository,
        runs: RunRepository,
        decisions: DecisionRepository,
        adapters: AdapterFactory,
        gate: ReleaseGate,
        signer: ReportSigner,
        audit: AuditLog,
        clock: Clock,
        metrics: RedTeamMetrics,
        default_tool_policy: PolicyEngine,
        llm_judge: LlmRubricJudge | None = None,
        max_probes_per_run: int = 5000,
        concurrency: int = 8,
        abort_after_consecutive_errors: int = 20,
    ) -> None:
        self.suites = suites
        self._targets = targets
        self._runs = runs
        self._decisions = decisions
        self._adapters = adapters
        self._gate = gate
        self._signer = signer
        self._audit = audit
        self._clock = clock
        self._metrics = metrics
        self._default_tool_policy = default_tool_policy
        self._llm = llm_judge
        self._calibration: CalibrationResult | None = None
        self._max_probes = max_probes_per_run
        self._concurrency = concurrency
        self._abort_after = abort_after_consecutive_errors

    @property
    def gate(self) -> ReleaseGate:
        return self._gate

    @property
    def signer(self) -> ReportSigner:
        return self._signer

    # ------------------------------------------------------------- targets

    async def register_target(self, registration: TargetRegistration, *, actor: str) -> Target:
        target = Target(
            **registration.model_dump(),
            id=new_id(),
            created_at=self._clock.now(),
            created_by=actor,
        )
        self._adapters.validate(target)
        await self._targets.add(target)
        await self._audit.record(
            actor=actor,
            action="target.register",
            resource=f"target:{target.id}",
            outcome="registered",
            details={"name": target.name, "kind": target.kind.value, "risk": target.risk.value},
        )
        return target

    async def get_target(self, target_id: str) -> Target:
        target = await self._targets.get(target_id)
        if target is None:
            raise NotFoundError(f"target {target_id} not found")
        return target

    async def list_targets(self, *, limit: int = 100, offset: int = 0) -> Sequence[Target]:
        return await self._targets.list(limit=limit, offset=offset)

    # -------------------------------------------------------------- suites

    def expand_suite(self, reference: str, *, seed: int) -> tuple[Suite, list[Probe]]:
        suite = self.suites.get(reference)
        return suite, expand(suite, seed)

    def _tool_policy(self, suite: Suite) -> PolicyEngine:
        return PolicyEngine(suite.tool_policy) if suite.tool_policy else self._default_tool_policy

    # ---------------------------------------------------------------- runs

    async def create_run(self, request: RunRequest, *, actor: str) -> Run:
        target = await self.get_target(request.target_id)
        suite = self.suites.get(request.suite)
        if suite.probe_count > self._max_probes:
            raise CapacityError(
                f"suite expands to {suite.probe_count} probes; limit is {self._max_probes}"
            )
        self._adapters.validate(target)
        run = Run(
            id=new_id(),
            target_id=target.id,
            target_version=request.target_version,
            suite_name=suite.name,
            suite_version=suite.version,
            suite_digest=suite.digest,
            seed=request.seed if request.seed is not None else secrets.randbelow(2**31),
            environment=request.environment,
            status=RunStatus.QUEUED,
            requested_by=actor,
            created_at=self._clock.now(),
            probe_count=suite.probe_count,
        )
        await self._runs.add(run)
        await self._audit.record(
            actor=actor,
            action="run.create",
            resource=f"run:{run.id}",
            outcome="queued",
            details={
                "target": target.id,
                "target_version": run.target_version,
                "suite": f"{suite.name}@{suite.version}",
                "suite_digest": suite.digest,
                "seed": run.seed,
                "environment": run.environment.value,
            },
        )
        return run

    async def get_run(self, run_id: str) -> Run:
        run = await self._runs.get(run_id)
        if run is None:
            raise NotFoundError(f"run {run_id} not found")
        return run

    async def list_runs(
        self,
        *,
        target_id: str | None = None,
        status: RunStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[Run]:
        return await self._runs.list(target_id=target_id, status=status, limit=limit, offset=offset)

    async def run_results(
        self, run_id: str, *, failed_only: bool = False, limit: int = 1000, offset: int = 0
    ) -> Sequence[ProbeResult]:
        await self.get_run(run_id)
        return await self._runs.results(run_id, failed_only=failed_only, limit=limit, offset=offset)

    async def _finish(self, run: Run, status: RunStatus, *, error: str | None = None) -> Run:
        finished = run.model_copy(
            update={"status": status, "completed_at": self._clock.now(), "error": error}
        )
        await self._runs.update(finished)
        self._metrics.runs.labels(status.value).inc()
        await self._audit.record(
            actor=PLATFORM_ACTOR,
            action="run.finish",
            resource=f"run:{run.id}",
            outcome=status.value,
            details={
                "error": error,
                "probes": finished.summary.total if finished.summary else 0,
                "failures": finished.summary.failures if finished.summary else 0,
                "errors": finished.summary.errors if finished.summary else 0,
            },
        )
        return finished

    async def execute_run(self, run_id: str) -> Run:
        run = await self.get_run(run_id)
        if run.status is not RunStatus.QUEUED:
            raise InvalidStateError(f"run {run_id} is {run.status}, not queued")
        run = run.model_copy(update={"status": RunStatus.RUNNING, "started_at": self._clock.now()})
        await self._runs.update(run)
        self._metrics.runs_active.inc()
        try:
            target = await self.get_target(run.target_id)
            suite = self.suites.get(f"{run.suite_name}@{run.suite_version}")
            if suite.digest != run.suite_digest:
                return await self._finish(
                    run, RunStatus.FAILED, error="suite content changed after the run was queued"
                )
            executor = ProbeExecutor(
                JudgePanel.build(self._tool_policy(suite), self._llm),
                metrics=self._metrics,
                concurrency=self._concurrency,
                abort_after_consecutive_errors=self._abort_after,
            )
            results = await executor.execute(
                run.id,
                expand(suite, run.seed),
                self._adapters.adapter(target),
                trace_source=self._adapters.trace_source(target),
                timeout_s=target.timeout_s,
                target_kind=target.kind.value,
            )
            for start in range(0, len(results), RESULT_BATCH):
                await self._runs.add_results(results[start : start + RESULT_BATCH])
            summary = summarize(
                results,
                confidence=self._gate.thresholds.confidence,
                resamples=self._gate.thresholds.bootstrap_resamples,
                seed=run.seed,
            )
            return await self._finish(
                run.model_copy(update={"summary": summary}), RunStatus.COMPLETED
            )
        except asyncio.CancelledError:
            try:
                await asyncio.shield(self._finish(run, RunStatus.ABORTED, error="cancelled"))
            except Exception:
                # Shutdown can interrupt a database call mid-flight; the run then stays
                # "running" until recover_interrupted() aborts it at the next start.
                log.exception("run_abort_not_recorded", run_id=run.id)
            raise
        except Exception as exc:
            # The run is the unit of failure: record why and keep the service up.
            await self._finish(run, RunStatus.FAILED, error=f"{type(exc).__name__}: {exc}")
            return await self.get_run(run.id)
        finally:
            self._metrics.runs_active.dec()

    async def recover_interrupted(self) -> int:
        """Runs a previous process left queued or running can never finish; close them."""
        recovered = 0
        for status in (RunStatus.QUEUED, RunStatus.RUNNING):
            for run in await self._runs.list(status=status, limit=10_000):
                await self._finish(run, RunStatus.ABORTED, error="interrupted by restart")
                recovered += 1
        return recovered

    # ---------------------------------------------------------------- gate

    async def _baseline(self, run: Run) -> Run | None:
        for decision in await self._decisions.list(target_id=run.target_id, limit=200):
            if decision.target_version == run.target_version or not decision.outcome.releasable:
                continue
            candidate = await self._runs.get(decision.run_id)
            if candidate is not None and candidate.suite_name == run.suite_name:
                return candidate
        return None

    def llm_status(self) -> LlmJudgeStatus:
        return LlmJudgeStatus(
            enabled=self._llm is not None,
            calibrated=bool(self._calibration and self._calibration.calibrated),
            kappa=self._calibration.kappa if self._calibration else None,
            binding=bool(self._llm and self._llm.binding),
        )

    async def evaluate_gate(self, run_id: str, *, requester: Principal) -> GateDecision:
        run = await self.get_run(run_id)
        if run.status is not RunStatus.COMPLETED or run.summary is None:
            raise InvalidStateError(f"run {run_id} is {run.status}; only completed runs are gated")
        target = await self.get_target(run.target_id)
        regression = compare(
            await self._baseline(run), run, confidence=self._gate.thresholds.confidence
        )
        advisory = await self._advisory_findings(run.id)
        evaluation = self._gate.evaluate(
            run=run,
            target=target,
            summary=run.summary,
            regression=regression,
            advisory_findings=advisory,
            requester=requester,
        )
        decision_id = new_id()
        report = EvaluationReport(
            report_id=decision_id,
            platform_version=__version__,
            generated_at=self._clock.now(),
            target_id=target.id,
            target_name=target.name,
            target_kind=target.kind,
            target_version=run.target_version,
            target_risk=target.risk,
            run_id=run.id,
            seed=run.seed,
            environment=run.environment,
            suite_name=run.suite_name,
            suite_version=run.suite_version,
            suite_digest=run.suite_digest,
            gate_policy=self._gate.thresholds.reference,
            decision_policy=self._gate.decision_policy,
            matched_rules=evaluation.decision.matched_rules,
            decision_reason=evaluation.decision.reason,
            summary=run.summary,
            assessments=evaluation.assessments,
            regression=regression,
            llm_judge=self.llm_status(),
            outcome=evaluation.outcome,
            requested_by=requester.subject,
        )
        signed = self._signer.sign(report)
        event = await self._audit.record(
            actor=requester.subject,
            action="gate.evaluate",
            resource=f"release:{target.name}@{run.target_version}",
            outcome=evaluation.outcome.value,
            details={
                "decision_id": decision_id,
                "run_id": run.id,
                "report_digest": signed.signature.digest,
                "key_id": signed.signature.key_id,
                "matched_rules": list(evaluation.decision.matched_rules),
                "decision_policy_digest": report.decision_policy.digest,
                "gate_policy_digest": report.gate_policy.digest,
                "facts": evaluation.facts,
            },
        )
        decision = GateDecision(
            id=decision_id,
            run_id=run.id,
            target_id=target.id,
            target_version=run.target_version,
            outcome=evaluation.outcome,
            requested_by=requester.subject,
            created_at=report.generated_at,
            audit_sequence=event.sequence,
            audit_hash=event.hash,
            signed_report=signed,
        )
        await self._decisions.add(decision)
        self._metrics.gate_decisions.labels(decision.outcome.value).inc()
        for stats in run.summary.categories:
            self._metrics.category_failure_upper.labels(target.name, stats.category.value).set(
                stats.wilson_high
            )
        return decision

    async def _advisory_findings(self, run_id: str) -> int:
        count, offset = 0, 0
        while True:
            page = await self._runs.results(run_id, limit=RESULT_BATCH, offset=offset)
            count += sum(1 for r in page if _advisory_fail(r.verdicts))
            if len(page) < RESULT_BATCH:
                return count
            offset += RESULT_BATCH

    async def get_decision(self, decision_id: str) -> GateDecision:
        decision = await self._decisions.get(decision_id)
        if decision is None:
            raise NotFoundError(f"gate decision {decision_id} not found")
        return decision

    async def list_decisions(
        self, *, target_id: str | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[GateDecision]:
        return await self._decisions.list(target_id=target_id, limit=limit, offset=offset)

    async def approve(self, decision_id: str, *, approver: Principal, reason: str) -> GateDecision:
        decision = await self.get_decision(decision_id)
        if decision.outcome is not GateOutcome.REQUIRE_APPROVAL:
            raise InvalidStateError(f"decision {decision_id} is {decision.outcome}, not approvable")
        if approver.subject == decision.requested_by:
            raise ForbiddenError("the requester of a release cannot approve it")
        event = await self._audit.record(
            actor=approver.subject,
            action="gate.approve",
            resource=f"gate-decision:{decision.id}",
            outcome=GateOutcome.APPROVED.value,
            details={
                "reason": reason,
                "report_digest": decision.signed_report.signature.digest,
                "run_id": decision.run_id,
            },
        )
        approval = Approval(
            approver=approver.subject, reason=reason, at=self._clock.now(), audit_hash=event.hash
        )
        report = decision.signed_report.report.model_copy(
            update={
                "outcome": GateOutcome.APPROVED,
                "approvals": (*decision.signed_report.report.approvals, approval),
            }
        )
        approved = decision.model_copy(
            update={"outcome": GateOutcome.APPROVED, "signed_report": self._signer.sign(report)}
        )
        await self._decisions.update(approved)
        self._metrics.gate_decisions.labels(GateOutcome.APPROVED.value).inc()
        return approved

    def verify(self, signed: SignedReport) -> Verification:
        return self._signer.verify(signed)

    # ----------------------------------------------------------- regression

    async def history(self, target_id: str, *, limit: int = 50) -> list[VersionPoint]:
        await self.get_target(target_id)
        points: list[VersionPoint] = []
        for decision in await self._decisions.list(target_id=target_id, limit=limit):
            report = decision.signed_report.report
            points.append(
                VersionPoint(
                    target_version=decision.target_version,
                    run_id=decision.run_id,
                    decision_id=decision.id,
                    outcome=decision.outcome,
                    decided_at=decision.created_at,
                    suite=f"{report.suite_name}@{report.suite_version}",
                    failure_upper_bounds={
                        c.category.value: c.wilson_high for c in report.summary.categories
                    },
                )
            )
        return points

    async def _latest_completed(self, target_id: str, version: str, suite: str | None) -> Run:
        for run in await self._runs.list(
            target_id=target_id, status=RunStatus.COMPLETED, limit=500
        ):
            if run.target_version == version and (suite is None or run.suite_name == suite):
                return run
        raise NotFoundError(f"no completed run for version {version}")

    async def compare_versions(
        self, target_id: str, *, baseline: str, candidate: str, suite: str | None = None
    ) -> RegressionReport:
        await self.get_target(target_id)
        candidate_run = await self._latest_completed(target_id, candidate, suite)
        baseline_run = await self._latest_completed(
            target_id, baseline, suite or candidate_run.suite_name
        )
        return compare(baseline_run, candidate_run, confidence=self._gate.thresholds.confidence)

    # --------------------------------------------------------- calibration

    async def calibrate_llm_judge(
        self, suite_reference: str, *, seed: int, examples: int, actor: str
    ) -> CalibrationResult:
        """Label probes with the deterministic judges on a half-weak reference agent,
        then measure how well the LLM judge agrees before letting it gate releases."""
        if self._llm is None:
            raise InvalidStateError("no LLM judge is configured (CRT_PROVIDERS_FILE)")
        suite, probes = self.expand_suite(suite_reference, seed=seed)
        policy = self._tool_policy(suite)
        agent = ReferenceAgent(
            ReferenceProfile(
                marker_leak_rate=0.5,
                secret_echo_rate=0.5,
                forbidden_tool_rate=0.5,
                approval_bypass_rate=0.5,
                seed=seed,
            ),
            policy,
        )
        deterministic = JudgePanel.build(policy)
        labelled: list[LabelledExample] = []
        for probe in probes[:examples]:
            response = await agent.invoke(probe.invocation)
            outcome, _ = await deterministic.assess(probe, response)
            labelled.append(
                LabelledExample(
                    probe=probe, response=response, violated=outcome is ProbeOutcome.FAIL
                )
            )
        result = await calibrate(self._llm, labelled)
        self._calibration = result
        self._llm.binding = result.calibrated
        await self._audit.record(
            actor=actor,
            action="judge.calibrate",
            resource="judge:llm_rubric",
            outcome="calibrated" if result.calibrated else "advisory",
            details=result.model_dump(mode="json"),
        )
        return result


def _advisory_fail(verdicts: tuple[JudgeVerdict, ...]) -> bool:
    return any(v.advisory and v.outcome is VerdictOutcome.FAIL for v in verdicts)
