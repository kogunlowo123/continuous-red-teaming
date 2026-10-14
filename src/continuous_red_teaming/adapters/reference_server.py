"""Network-facing reference agent for end-to-end validation of the adapters.

Serves one ReferenceAgent over every protocol the platform speaks:

* ``POST /invoke``          HTTP agent wire contract
* ``POST /a2a``             A2A JSON-RPC ``message/send``
* ``/mcp``                  MCP streamable HTTP, tool ``run_task``
* ``GET /trace``            tool calls per session (trace contract)
* ``GET /.well-known/agent-card.json``

Run with ``python -m continuous_red_teaming.adapters.reference_server``; the
profile comes from ``CRT_REFERENCE_PROFILE`` (JSON). It is a calibration
target for staging and CI, not an agent for production work.
"""

from __future__ import annotations

import contextlib
import os
from collections import OrderedDict
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

from agentic_core.policy import PolicyEngine, PolicySet
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from continuous_red_teaming import __version__
from continuous_red_teaming.adapters.a2a import STATE_MAP
from continuous_red_teaming.adapters.base import AgentReply
from continuous_red_teaming.adapters.reference import ReferenceAgent
from continuous_red_teaming.domain.models import (
    ContextDocument,
    ProbeInvocation,
    ReferenceProfile,
    TargetResponse,
    ToolCall,
)

MAX_TRACED_SESSIONS = 10_000


class InvocationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=128)
    task: str = Field(min_length=1, max_length=8000)
    context: list[ContextDocument] = Field(default_factory=list, max_length=16)


def _reply(response: TargetResponse) -> AgentReply:
    return AgentReply(
        output=response.output, status=response.status, tool_calls=response.tool_calls
    )


def create_reference_app(
    agent: ReferenceAgent, *, allowed_hosts: Sequence[str] = ("127.0.0.1:*", "localhost:*")
) -> FastAPI:
    traces: OrderedDict[str, tuple[ToolCall, ...]] = OrderedDict()

    async def run(invocation: ProbeInvocation) -> AgentReply:
        response = await agent.invoke(invocation)
        traces[invocation.session_id] = response.tool_calls
        traces.move_to_end(invocation.session_id)
        while len(traces) > MAX_TRACED_SESSIONS:
            traces.popitem(last=False)
        return _reply(response)

    mcp = MCPServer("reference-agent", version=__version__, log_level="WARNING")

    @mcp.tool(description="Perform a task over the supplied context documents.")
    async def run_task(
        session_id: str, task: str, context: list[ContextDocument] | None = None
    ) -> AgentReply:
        return await run(
            ProbeInvocation(session_id=session_id, task=task, context=tuple(context or ()))
        )

    mcp_app = mcp.streamable_http_app(
        streamable_http_path="/",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(allowed_hosts=list(allowed_hosts)),
    )

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async with mcp.session_manager.run():
            yield

    app = FastAPI(title="Reference agent", version=__version__, lifespan=lifespan)
    app.mount("/mcp", mcp_app)

    @app.post("/invoke")
    async def invoke(body: InvocationIn) -> AgentReply:
        return await run(
            ProbeInvocation(session_id=body.session_id, task=body.task, context=tuple(body.context))
        )

    @app.get("/trace")
    async def trace(session_id: str) -> dict[str, Any]:
        calls = traces.get(session_id, ())
        return {"tool_calls": [c.model_dump(mode="json") for c in calls]}

    @app.get("/.well-known/agent-card.json")
    async def card() -> dict[str, Any]:
        return {
            "protocolVersion": "0.3.0",
            "name": "reference-agent",
            "description": "Calibration target with configured, measurable weaknesses.",
            "url": "/a2a",
            "version": __version__,
            "capabilities": {"streaming": False, "pushNotifications": False},
            "defaultInputModes": ["text", "data"],
            "defaultOutputModes": ["text", "data"],
            "skills": [
                {
                    "id": "run-task",
                    "name": "Run task",
                    "description": "Perform a task over supplied context documents.",
                    "tags": ["calibration"],
                }
            ],
            "securitySchemes": {},
        }

    @app.post("/a2a")
    async def a2a(request: Request) -> JSONResponse:
        try:
            envelope = await request.json()
        except ValueError:
            return _rpc_error(None, -32700, "parse error")
        rpc_id = envelope.get("id") if isinstance(envelope, dict) else None
        if not isinstance(envelope, dict) or envelope.get("method") != "message/send":
            return _rpc_error(rpc_id, -32601, "method not found")
        try:
            invocation = _invocation_from_message(envelope["params"]["message"])
        except (KeyError, TypeError, ValidationError):
            return _rpc_error(rpc_id, -32602, "invalid params")
        reply = await run(invocation)
        state = next(k for k, v in STATE_MAP.items() if v is reply.status)
        task = {
            "kind": "task",
            "id": invocation.session_id,
            "contextId": invocation.session_id,
            "status": {"state": state},
            "artifacts": [
                {
                    "artifactId": f"reply-{invocation.session_id}",
                    "parts": [
                        {"kind": "text", "text": reply.output},
                        {
                            "kind": "data",
                            "data": {
                                "tool_calls": [c.model_dump(mode="json") for c in reply.tool_calls]
                            },
                        },
                    ],
                }
            ],
        }
        return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": task})

    return app


def _rpc_error(rpc_id: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
    )


def _invocation_from_message(message: dict[str, Any]) -> ProbeInvocation:
    parts = message["parts"]
    task = "\n".join(p["text"] for p in parts if p.get("kind") == "text")
    context: list[ContextDocument] = []
    for part in parts:
        if part.get("kind") == "data" and isinstance(part.get("data"), dict):
            context.extend(ContextDocument.model_validate(d) for d in part["data"]["context"])
    body = InvocationIn(session_id=str(message["messageId"]), task=task, context=context)
    return ProbeInvocation(session_id=body.session_id, task=body.task, context=tuple(body.context))


def main() -> None:  # pragma: no cover - process entry point
    import uvicorn  # noqa: PLC0415

    profile = ReferenceProfile.model_validate_json(os.environ.get("CRT_REFERENCE_PROFILE", "{}"))
    policy_file = Path(
        os.environ.get("CRT_TARGET_TOOL_POLICY_FILE", "policies/target-tool-policy.yaml")
    )
    agent = ReferenceAgent(profile, PolicyEngine(PolicySet.from_file(policy_file)))
    hosts = os.environ.get("CRT_REFERENCE_ALLOWED_HOSTS", "127.0.0.1:*,localhost:*").split(",")
    uvicorn.run(
        create_reference_app(agent, allowed_hosts=hosts),
        host=os.environ.get("CRT_REFERENCE_HOST", "127.0.0.1"),
        port=int(os.environ.get("CRT_REFERENCE_PORT", "8090")),
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
