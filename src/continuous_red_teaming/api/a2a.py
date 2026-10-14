"""A2A interface: Agent Card and JSON-RPC 2.0 ``message/send`` / ``tasks/get``.

Skills are selected with a data part ``{"skill": "<id>", ...arguments}``:

* ``start-validation-run``  -> Task (submitted); poll with ``tasks/get``
* ``evaluate-release-gate`` -> Task (completed, or input-required when a
  human must approve the release)
* ``compare-versions``      -> Task (completed) with the regression report

Task ids are run ids or gate-decision ids. Authentication failures are HTTP
401 with an OAuth error body; authorization failures are JSON-RPC errors.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from continuous_red_teaming import __version__
from continuous_red_teaming.application.service import RunRequest
from continuous_red_teaming.domain.errors import NotFoundError, RedTeamError, UnauthorizedError
from continuous_red_teaming.domain.models import GateDecision, GateOutcome, Run, RunStatus
from continuous_red_teaming.runtime.container import Container
from continuous_red_teaming.security.access import Action
from continuous_red_teaming.security.auth import Principal

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
TASK_NOT_FOUND = -32001
FORBIDDEN = -32003
SERVER_ERROR = -32000

RUN_STATES = {
    RunStatus.QUEUED: "submitted",
    RunStatus.RUNNING: "working",
    RunStatus.COMPLETED: "completed",
    RunStatus.ABORTED: "canceled",
    RunStatus.FAILED: "failed",
}

router = APIRouter()


class CompareArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=64)
    baseline: str = Field(min_length=1, max_length=64)
    candidate: str = Field(min_length=1, max_length=64)


class GateArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1, max_length=64)


def agent_card(container: Container) -> dict[str, Any]:
    base = container.settings.public_url_str
    return {
        "protocolVersion": "0.3.0",
        "name": "continuous-red-teaming",
        "description": (
            "Validates AI agent releases with benign synthetic probes (canary markers, "
            "forbidden-tool requests, out-of-scope actions), scores failure rates with "
            "confidence intervals and returns a signed release-gate decision."
        ),
        "url": f"{base}/a2a",
        "preferredTransport": "JSONRPC",
        "version": __version__,
        "provider": {"organization": "kogunlowo123", "url": base},
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json"],
        "securitySchemes": {
            "bearer": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Identity-fabric agent credential or enterprise OIDC token",
            }
        },
        "security": [{"bearer": []}],
        "skills": [
            {
                "id": "start-validation-run",
                "name": "Start validation run",
                "description": "Queue a probe suite against a registered target version.",
                "tags": ["validation", "red-teaming"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "evaluate-release-gate",
                "name": "Evaluate release gate",
                "description": "Gate a completed run; returns pass, fail or require_approval.",
                "tags": ["release", "governance"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "compare-versions",
                "name": "Compare versions",
                "description": "Regression analysis between two target versions.",
                "tags": ["regression"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
        ],
    }


def _error(rpc_id: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
    )


def _result(rpc_id: Any, result: dict[str, Any]) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


def _task(task_id: str, state: str, data: dict[str, Any], context_id: str) -> dict[str, Any]:
    return {
        "kind": "task",
        "id": task_id,
        "contextId": context_id,
        "status": {"state": state},
        "artifacts": [
            {"artifactId": f"{task_id}-result", "parts": [{"kind": "data", "data": data}]}
        ],
    }


def run_task(run: Run) -> dict[str, Any]:
    return _task(run.id, RUN_STATES[run.status], run.model_dump(mode="json"), run.target_id)


def decision_task(decision: GateDecision) -> dict[str, Any]:
    state = "input-required" if decision.outcome is GateOutcome.REQUIRE_APPROVAL else "completed"
    data = {
        "decision_id": decision.id,
        "outcome": decision.outcome.value,
        "releasable": decision.outcome.releasable,
        "run_id": decision.run_id,
        "report_digest": decision.signed_report.signature.digest,
        "assessments": [
            a.model_dump(mode="json") for a in decision.signed_report.report.assessments
        ],
    }
    return _task(decision.id, state, data, decision.target_id)


def _skill_arguments(params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    message = params.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("parts"), list):
        raise ValueError("params.message.parts is required")
    for part in message["parts"]:
        data = part.get("data") if isinstance(part, dict) and part.get("kind") == "data" else None
        if isinstance(data, dict) and isinstance(data.get("skill"), str):
            arguments = {k: v for k, v in data.items() if k != "skill"}
            return data["skill"], arguments
    raise ValueError("a data part with a 'skill' field is required")


async def _send(c: Container, who: Principal, params: dict[str, Any]) -> dict[str, Any]:
    skill, arguments = _skill_arguments(params)
    if skill == "start-validation-run":
        request = RunRequest.model_validate(arguments)
        await c.access.authorize(
            who, Action.RUNS_START, resource_type="target", resource_id=request.target_id
        )
        c.scheduler.ensure_capacity()
        run = await c.service.create_run(request, actor=who.subject)
        c.scheduler.submit(run.id)
        return run_task(run)
    if skill == "evaluate-release-gate":
        gate = GateArgs.model_validate(arguments)
        await c.access.authorize(
            who, Action.GATE_EVALUATE, resource_type="run", resource_id=gate.run_id
        )
        return decision_task(await c.service.evaluate_gate(gate.run_id, requester=who))
    if skill == "compare-versions":
        args = CompareArgs.model_validate(arguments)
        await c.access.authorize(
            who, Action.RUNS_READ, resource_type="target", resource_id=args.target_id
        )
        report = await c.service.compare_versions(
            args.target_id, baseline=args.baseline, candidate=args.candidate
        )
        return _task(
            f"compare-{args.target_id}-{args.candidate}",
            "completed",
            report.model_dump(mode="json"),
            args.target_id,
        )
    raise ValueError(f"unknown skill {skill!r}")


async def _get(c: Container, who: Principal, params: dict[str, Any]) -> dict[str, Any]:
    task_id = params.get("id")
    if not isinstance(task_id, str) or not task_id:
        raise ValueError("params.id is required")
    await c.access.authorize(who, Action.RUNS_READ, resource_type="task", resource_id=task_id)
    try:
        return run_task(await c.service.get_run(task_id))
    except NotFoundError:
        return decision_task(await c.service.get_decision(task_id))


@router.get("/.well-known/agent-card.json", tags=["a2a"])
async def card(request: Request) -> dict[str, Any]:
    return agent_card(request.app.state.container)


async def _dispatch(c: Container, who: Principal, envelope: Any) -> JSONResponse:
    if not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0":
        return _error(None, INVALID_REQUEST, "invalid JSON-RPC 2.0 request")
    rpc_id = envelope.get("id")
    method = envelope.get("method")
    params = envelope.get("params")
    handlers = {"message/send": _send, "tasks/get": _get}
    handler = handlers.get(method) if isinstance(method, str) else None
    if handler is None:
        return _error(rpc_id, METHOD_NOT_FOUND, f"method {method!r} not found")
    if not isinstance(params, dict):
        return _error(rpc_id, INVALID_PARAMS, "params must be an object")
    try:
        return _result(rpc_id, await handler(c, who, params))
    except (ValueError, RedTeamError) as exc:
        return _error(rpc_id, *_rpc_failure(exc))


def _rpc_failure(exc: ValueError | RedTeamError) -> tuple[int, str]:
    if isinstance(exc, ValueError):
        return INVALID_PARAMS, str(exc).splitlines()[0]
    if isinstance(exc, NotFoundError):
        return TASK_NOT_FOUND, exc.message
    code = FORBIDDEN if exc.status in {401, 403} else SERVER_ERROR
    return code, f"{exc.code}: {exc.message}"


@router.post("/a2a", tags=["a2a"], response_model=None)
async def a2a(request: Request) -> JSONResponse:
    c: Container = request.app.state.container
    try:
        who = await c.authenticator.authenticate(request.headers.get("authorization"))
    except UnauthorizedError as exc:
        return JSONResponse(
            {"error": exc.code, "error_description": exc.message},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        envelope = await request.json()
    except ValueError:
        return _error(None, PARSE_ERROR, "parse error")
    return await _dispatch(c, who, envelope)
