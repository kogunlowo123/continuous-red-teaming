"""MCP tools (official ``mcp`` SDK, streamable HTTP, mounted at ``/mcp/``).

Each tool has typed input and output schemas, authenticates the bearer
token on the MCP request, authorizes the action through the same
AccessController as the REST API, and writes an audit event.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict, Field
from starlette.applications import Starlette

from continuous_red_teaming import __version__
from continuous_red_teaming.application.service import RunRequest
from continuous_red_teaming.domain.models import (
    Category,
    CategoryVerdict,
    Environment,
    GateDecision,
    GateOutcome,
    RegressionReport,
    Run,
    RunStatus,
)
from continuous_red_teaming.runtime.container import Container
from continuous_red_teaming.security.access import Action
from continuous_red_teaming.security.auth import Principal


class SuiteSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    digest: str
    probe_count: int
    categories: list[Category]


class SuiteCatalogOut(BaseModel):
    suites: list[SuiteSummary]


class CategoryOut(BaseModel):
    category: Category
    conclusive: int
    failures: int
    failure_rate: float
    wilson_high: float


class RunOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    status: RunStatus
    target_id: str
    target_version: str
    suite: str
    probe_count: int
    failures: int = 0
    errors: int = 0
    categories: list[CategoryOut] = Field(default_factory=list)
    error: str | None = None

    @classmethod
    def of(cls, run: Run) -> RunOut:
        summary = run.summary
        return cls(
            run_id=run.id,
            status=run.status,
            target_id=run.target_id,
            target_version=run.target_version,
            suite=f"{run.suite_name}@{run.suite_version}",
            probe_count=run.probe_count,
            failures=summary.failures if summary else 0,
            errors=summary.errors if summary else 0,
            categories=[
                CategoryOut(
                    category=c.category,
                    conclusive=c.conclusive,
                    failures=c.failures,
                    failure_rate=c.failure_rate,
                    wilson_high=c.wilson_high,
                )
                for c in (summary.categories if summary else ())
            ],
            error=run.error,
        )


class AssessmentOut(BaseModel):
    category: Category
    verdict: CategoryVerdict
    reason: str


class DecisionOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision_id: str
    outcome: GateOutcome
    releasable: bool
    run_id: str
    target_version: str
    matched_rules: list[str]
    reason: str
    assessments: list[AssessmentOut]
    report_digest: str
    signing_key_id: str

    @classmethod
    def of(cls, decision: GateDecision) -> DecisionOut:
        report = decision.signed_report.report
        return cls(
            decision_id=decision.id,
            outcome=decision.outcome,
            releasable=decision.outcome.releasable,
            run_id=decision.run_id,
            target_version=decision.target_version,
            matched_rules=list(report.matched_rules),
            reason=report.decision_reason,
            assessments=[
                AssessmentOut(category=a.category, verdict=a.verdict, reason=a.reason)
                for a in report.assessments
            ],
            report_digest=decision.signed_report.signature.digest,
            signing_key_id=decision.signed_report.signature.key_id,
        )


ContainerAccessor = Callable[[], Container]


def build_mcp_server(container_of: ContainerAccessor) -> MCPServer:
    server = MCPServer(
        "continuous-red-teaming",
        version=__version__,
        instructions=(
            "Validate AI agent releases with benign synthetic probes and gate promotion "
            "on per-category failure-rate thresholds. Runs execute asynchronously: start a "
            "run, poll get_run until it completes, then evaluate_release_gate."
        ),
        log_level="WARNING",
    )

    async def guard(
        ctx: Context, action: str, resource_type: str, resource_id: str
    ) -> tuple[Container, Principal]:
        c = container_of()
        headers = ctx.headers or {}
        who = await c.authenticator.authenticate(headers.get("authorization"))
        await c.access.authorize(who, action, resource_type=resource_type, resource_id=resource_id)
        return c, who

    async def audited(c: Container, who: Principal, tool: str, resource: str, outcome: str) -> None:
        await c.audit.record(
            actor=who.subject,
            action=f"mcp.{tool}",
            resource=resource,
            outcome=outcome,
            details={"principal_kind": who.kind.value},
        )

    @server.tool(description="List the versioned probe suites available for validation runs.")
    async def list_suites(ctx: Context) -> SuiteCatalogOut:
        c, who = await guard(ctx, Action.SUITES_READ, "redteam", "*")
        suites = [
            SuiteSummary(
                name=s.name,
                version=s.version,
                digest=s.digest,
                probe_count=s.probe_count,
                categories=list(s.categories),
            )
            for s in c.service.suites.all()
        ]
        await audited(c, who, "list_suites", "suites", "ok")
        return SuiteCatalogOut(suites=suites)

    @server.tool(description="Queue a validation run of a suite against a registered target.")
    async def start_validation_run(
        ctx: Context,
        *,
        target_id: str,
        target_version: str,
        suite: str,
        seed: int | None = None,
        environment: Environment = Environment.STAGING,
    ) -> RunOut:
        request = RunRequest(
            target_id=target_id,
            target_version=target_version,
            suite=suite,
            seed=seed,
            environment=environment,
        )
        c, who = await guard(ctx, Action.RUNS_START, "target", target_id)
        c.scheduler.ensure_capacity()
        run = await c.service.create_run(request, actor=who.subject)
        c.scheduler.submit(run.id)
        await audited(c, who, "start_validation_run", f"run:{run.id}", "queued")
        return RunOut.of(run)

    @server.tool(description="Status and per-category results of a validation run.")
    async def get_run(run_id: str, ctx: Context) -> RunOut:
        c, who = await guard(ctx, Action.RUNS_READ, "run", run_id)
        run = await c.service.get_run(run_id)
        await audited(c, who, "get_run", f"run:{run_id}", run.status.value)
        return RunOut.of(run)

    @server.tool(description="Evaluate the release gate for a completed run (signed report).")
    async def evaluate_release_gate(run_id: str, ctx: Context) -> DecisionOut:
        c, who = await guard(ctx, Action.GATE_EVALUATE, "run", run_id)
        decision = await c.service.evaluate_gate(run_id, requester=who)
        await audited(c, who, "evaluate_release_gate", f"run:{run_id}", decision.outcome.value)
        return DecisionOut.of(decision)

    @server.tool(description="Compare failure rates of two target versions (Newcombe intervals).")
    async def compare_versions(
        target_id: str, baseline: str, candidate: str, ctx: Context
    ) -> RegressionReport:
        c, who = await guard(ctx, Action.RUNS_READ, "target", target_id)
        report = await c.service.compare_versions(target_id, baseline=baseline, candidate=candidate)
        await audited(c, who, "compare_versions", f"target:{target_id}", "ok")
        return report

    return server


def mcp_app(server: MCPServer, allowed_hosts: Sequence[str]) -> Starlette:
    return server.streamable_http_app(
        streamable_http_path="/",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(allowed_hosts=list(allowed_hosts)),
    )
