"""HTTP routes.

Every ``/v1`` route authenticates the caller (enterprise OIDC, CI workload
OIDC, or an identity-fabric agent credential) and authorizes the action
through the AccessController before touching the service.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from continuous_red_teaming.api.schemas import (
    ApproveRequest,
    CalibrateRequest,
    DecisionList,
    Expansion,
    History,
    ProbeResultList,
    RunList,
    SampleSize,
    SuiteList,
    SuiteView,
    TargetList,
)
from continuous_red_teaming.application.service import RunRequest
from continuous_red_teaming.domain.models import (
    GateDecision,
    LlmJudgeStatus,
    RegressionReport,
    Run,
    RunStatus,
    SignedReport,
    Target,
    TargetRegistration,
)
from continuous_red_teaming.domain.statistics import zero_failure_sample_size
from continuous_red_teaming.gate.report import Verification
from continuous_red_teaming.judges.llm import CalibrationResult
from continuous_red_teaming.runtime.container import Container
from continuous_red_teaming.security.access import Action
from continuous_red_teaming.security.auth import Principal

router = APIRouter()


def container(request: Request) -> Container:
    value: Container = request.app.state.container
    return value


async def principal(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> Principal:
    return await container(request).authenticator.authenticate(authorization)


Deps = Annotated[Container, Depends(container)]
Caller = Annotated[Principal, Depends(principal)]
Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Identifier = Annotated[str, Query(min_length=1, max_length=64)]


# --------------------------------------------------------------------- suites


@router.get("/v1/suites", tags=["suites"])
async def list_suites(c: Deps, who: Caller) -> SuiteList:
    await c.access.authorize(who, Action.SUITES_READ)
    return SuiteList(items=[SuiteView.of(s) for s in c.service.suites.all()])


@router.get("/v1/suites/{reference}", tags=["suites"])
async def get_suite(reference: str, c: Deps, who: Caller) -> SuiteView:
    await c.access.authorize(who, Action.SUITES_READ)
    return SuiteView.of(c.service.suites.get(reference))


@router.get("/v1/suites/{reference}/expansion", tags=["suites"])
async def expand_suite(
    reference: str,
    c: Deps,
    who: Caller,
    seed: Annotated[int, Query(ge=0, le=2**31 - 1)] = 0,
    limit: Limit = 50,
) -> Expansion:
    """Preview the deterministic probes a run with this seed will send."""
    await c.access.authorize(who, Action.SUITES_READ)
    suite, probes = c.service.expand_suite(reference, seed=seed)
    return Expansion(
        suite=suite.name,
        version=suite.version,
        digest=suite.digest,
        seed=seed,
        probe_count=len(probes),
        probes=probes[:limit],
    )


# -------------------------------------------------------------------- targets


@router.post("/v1/targets", status_code=201, tags=["targets"])
async def register_target(body: TargetRegistration, c: Deps, who: Caller) -> Target:
    await c.access.authorize(who, Action.TARGETS_REGISTER, resource_type="target")
    return await c.service.register_target(body, actor=who.subject)


@router.get("/v1/targets", tags=["targets"])
async def list_targets(c: Deps, who: Caller, limit: Limit = 100, offset: Offset = 0) -> TargetList:
    await c.access.authorize(who, Action.TARGETS_READ, resource_type="target")
    items = await c.service.list_targets(limit=limit, offset=offset)
    return TargetList(items=list(items), limit=limit, offset=offset)


@router.get("/v1/targets/{target_id}", tags=["targets"])
async def get_target(target_id: str, c: Deps, who: Caller) -> Target:
    await c.access.authorize(
        who, Action.TARGETS_READ, resource_type="target", resource_id=target_id
    )
    return await c.service.get_target(target_id)


@router.get("/v1/targets/{target_id}/history", tags=["regression"])
async def history(target_id: str, c: Deps, who: Caller, limit: Limit = 50) -> History:
    await c.access.authorize(who, Action.GATE_READ, resource_type="target", resource_id=target_id)
    return History(target_id=target_id, points=await c.service.history(target_id, limit=limit))


@router.get("/v1/targets/{target_id}/comparison", tags=["regression"])
async def compare_versions(
    target_id: str,
    *,
    c: Deps,
    who: Caller,
    baseline: Identifier,
    candidate: Identifier,
    suite: Annotated[str | None, Query(max_length=64)] = None,
) -> RegressionReport:
    await c.access.authorize(who, Action.RUNS_READ, resource_type="target", resource_id=target_id)
    return await c.service.compare_versions(
        target_id, baseline=baseline, candidate=candidate, suite=suite
    )


# ----------------------------------------------------------------------- runs


@router.post("/v1/runs", status_code=202, tags=["runs"])
async def start_run(body: RunRequest, c: Deps, who: Caller) -> Run:
    await c.access.authorize(
        who,
        Action.RUNS_START,
        resource_type="target",
        resource_id=body.target_id,
        attributes={"environment": body.environment.value},
    )
    c.scheduler.ensure_capacity()
    run = await c.service.create_run(body, actor=who.subject)
    c.scheduler.submit(run.id)
    return run


@router.get("/v1/runs", tags=["runs"])
async def list_runs(
    *,
    c: Deps,
    who: Caller,
    target_id: Annotated[str | None, Query(max_length=64)] = None,
    status: RunStatus | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> RunList:
    await c.access.authorize(who, Action.RUNS_READ, resource_type="run")
    items = await c.service.list_runs(
        target_id=target_id, status=status, limit=limit, offset=offset
    )
    return RunList(items=list(items), limit=limit, offset=offset)


@router.get("/v1/runs/{run_id}", tags=["runs"])
async def get_run(run_id: str, c: Deps, who: Caller) -> Run:
    await c.access.authorize(who, Action.RUNS_READ, resource_type="run", resource_id=run_id)
    return await c.service.get_run(run_id)


@router.get("/v1/runs/{run_id}/results", tags=["runs"])
async def run_results(
    run_id: str,
    *,
    c: Deps,
    who: Caller,
    failed_only: bool = False,
    limit: Limit = 100,
    offset: Offset = 0,
) -> ProbeResultList:
    await c.access.authorize(who, Action.RUNS_READ, resource_type="run", resource_id=run_id)
    items = await c.service.run_results(run_id, failed_only=failed_only, limit=limit, offset=offset)
    return ProbeResultList(items=list(items), limit=limit, offset=offset)


# ----------------------------------------------------------------------- gate


@router.post("/v1/runs/{run_id}/gate", status_code=201, tags=["gate"])
async def evaluate_gate(run_id: str, c: Deps, who: Caller) -> GateDecision:
    """Evaluate the release gate for a completed run and issue a signed report."""
    await c.access.authorize(who, Action.GATE_EVALUATE, resource_type="run", resource_id=run_id)
    return await c.service.evaluate_gate(run_id, requester=who)


@router.get("/v1/gate/decisions", tags=["gate"])
async def list_decisions(
    c: Deps,
    who: Caller,
    target_id: Annotated[str | None, Query(max_length=64)] = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> DecisionList:
    await c.access.authorize(who, Action.GATE_READ, resource_type="gate-decision")
    items = await c.service.list_decisions(target_id=target_id, limit=limit, offset=offset)
    return DecisionList(items=list(items), limit=limit, offset=offset)


@router.get("/v1/gate/decisions/{decision_id}", tags=["gate"])
async def get_decision(decision_id: str, c: Deps, who: Caller) -> GateDecision:
    await c.access.authorize(
        who, Action.GATE_READ, resource_type="gate-decision", resource_id=decision_id
    )
    return await c.service.get_decision(decision_id)


@router.get("/v1/gate/decisions/{decision_id}/report", tags=["gate"])
async def get_report(decision_id: str, c: Deps, who: Caller) -> SignedReport:
    await c.access.authorize(
        who, Action.GATE_READ, resource_type="gate-decision", resource_id=decision_id
    )
    return (await c.service.get_decision(decision_id)).signed_report


@router.post("/v1/gate/decisions/{decision_id}/approve", tags=["gate"])
async def approve(decision_id: str, body: ApproveRequest, c: Deps, who: Caller) -> GateDecision:
    """Human sign-off for a decision that requires approval (two-person rule)."""
    decision = await c.service.get_decision(decision_id)
    await c.access.authorize(
        who,
        Action.GATE_APPROVE,
        resource_type="gate-decision",
        resource_id=decision_id,
        attributes={"requested_by": decision.requested_by},
    )
    return await c.service.approve(decision_id, approver=who, reason=body.reason)


@router.post("/v1/reports/verify", tags=["gate"])
async def verify_report(body: SignedReport, c: Deps, who: Caller) -> Verification:
    await c.access.authorize(who, Action.GATE_READ, resource_type="report")
    return c.service.verify(body)


@router.get("/v1/gate/sample-size", tags=["gate"])
async def sample_size(
    c: Deps,
    who: Caller,
    max_failure_rate: Annotated[float, Query(gt=0.0005, lt=0.5)],
    confidence: Annotated[float, Query(ge=0.8, le=0.999)] = 0.95,
) -> SampleSize:
    """Conclusive probes a category needs before a zero-failure run can pass."""
    await c.access.authorize(who, Action.SUITES_READ)
    return SampleSize(
        max_failure_rate=max_failure_rate,
        confidence=confidence,
        zero_failure_probes=zero_failure_sample_size(max_failure_rate, confidence),
    )


# --------------------------------------------------------------------- judges


@router.get("/v1/judges/llm", tags=["judges"])
async def llm_judge(c: Deps, who: Caller) -> LlmJudgeStatus:
    await c.access.authorize(who, Action.GATE_READ, resource_type="judge")
    return c.service.llm_status()


@router.post("/v1/judges/llm/calibration", tags=["judges"])
async def calibrate_llm_judge(body: CalibrateRequest, c: Deps, who: Caller) -> CalibrationResult:
    await c.access.authorize(who, Action.JUDGES_CALIBRATE, resource_type="judge")
    return await c.service.calibrate_llm_judge(
        body.suite, seed=body.seed, examples=body.examples, actor=who.subject
    )


# ------------------------------------------------------------------ discovery


@router.get("/.well-known/report-signing-keys", tags=["discovery"])
async def signing_keys(c: Deps) -> dict[str, object]:
    """Public keys that verify evaluation report signatures (JWKS, OKP/Ed25519)."""
    return c.service.signer.jwks()


# ----------------------------------------------------------------- operations


@router.get("/healthz", tags=["operations"], include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["operations"], include_in_schema=False)
async def readyz(c: Deps, response: Response) -> dict[str, str]:
    try:
        async with c.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "database unavailable"}
    return {"status": "ready"}


@router.get("/metrics", tags=["operations"], include_in_schema=False)
async def metrics(c: Deps) -> Response:
    return Response(generate_latest(c.metrics.registry), media_type=CONTENT_TYPE_LATEST)
