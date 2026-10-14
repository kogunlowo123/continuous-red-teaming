"""Target wire contract and outbound credentials shared by all adapters.

Agent invocation request (HTTP body, MCP tool arguments, A2A data part)::

    {"session_id": "...", "task": "...", "context": [
        {"id": "doc-0", "source": "...", "content": "...", "trust": "external"}]}

Agent response (HTTP body, MCP structured content, A2A data part)::

    {"output": "...", "status": "completed|require_approval|refused|error",
     "tool_calls": [{"name": "...", "arguments": {...},
                     "status": "executed|proposed|blocked", "approval_id": null}]}

The invocation never states the probe's category or which values are
protected; the target must behave the same as it would in production.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from continuous_red_teaming.domain.errors import AdapterError, DependencyUnavailableError
from continuous_red_teaming.domain.models import (
    ProbeInvocation,
    ResponseStatus,
    TargetResponse,
    ToolCall,
)
from continuous_red_teaming.integrations.identity_fabric import IdentityFabricClient

MAX_OUTPUT_CHARS = 200_000
MAX_TOOL_CALLS = 200


class AgentReply(BaseModel):
    """Validated agent response body (``schemas/agent-reply.schema.json``)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    output: str = Field(default="", max_length=MAX_OUTPUT_CHARS)
    status: ResponseStatus = ResponseStatus.COMPLETED
    tool_calls: tuple[ToolCall, ...] = Field(default=(), max_length=MAX_TOOL_CALLS)


def invocation_payload(invocation: ProbeInvocation) -> dict[str, Any]:
    return invocation.model_dump(mode="json")


def parse_reply(payload: Any, *, latency_ms: float, trace_source: str) -> TargetResponse:
    if not isinstance(payload, Mapping):
        raise AdapterError("target reply is not a JSON object", retryable=False)
    try:
        reply = AgentReply.model_validate(payload)
    except ValidationError as exc:
        raise AdapterError(
            f"target reply violates the wire contract: {exc}", retryable=False
        ) from exc
    return TargetResponse(
        output=reply.output,
        tool_calls=reply.tool_calls,
        status=reply.status,
        latency_ms=latency_ms,
        trace_source=trace_source,
    )


class CredentialProvider(Protocol):
    async def headers(self) -> dict[str, str]: ...


class NoCredentials:
    async def headers(self) -> dict[str, str]:
        return {}


class EnvBearer:
    """Bearer token read from a named environment variable at call time."""

    def __init__(self, variable: str, env: Mapping[str, str] | None = None) -> None:
        self._variable = variable
        self._env = env

    async def headers(self) -> dict[str, str]:
        source = os.environ if self._env is None else self._env
        value = source.get(self._variable)
        if not value:
            raise DependencyUnavailableError(f"environment variable {self._variable} is not set")
        return {"Authorization": f"Bearer {value}"}


class FabricBearer:
    """The platform's own identity-fabric credential."""

    def __init__(self, fabric: IdentityFabricClient) -> None:
        self._fabric = fabric

    async def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self._fabric.access_token()}"}
