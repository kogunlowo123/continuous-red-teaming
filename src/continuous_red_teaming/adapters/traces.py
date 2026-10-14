"""Independent tool-call traces.

A target's self-reported tool calls are not sufficient evidence on their
own: a target that executes a forbidden tool and omits it from its reply
would pass. When a trace endpoint is registered (for example the MCP/A2A
gateway's audit query API), the executor merges the calls recorded there into
the response before judging, and marks the evidence as externally traced.

Trace endpoint contract: ``GET <url>?session_id=<id>`` returns
``{"tool_calls": [<agent reply tool call>, ...]}``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

import httpx
from pydantic import TypeAdapter, ValidationError

from continuous_red_teaming.adapters.base import MAX_TOOL_CALLS, CredentialProvider
from continuous_red_teaming.domain.errors import AdapterError
from continuous_red_teaming.domain.models import TargetResponse, ToolCall

_CALLS = TypeAdapter(list[ToolCall])


class HttpTraceSource:
    def __init__(
        self,
        url: str,
        *,
        client: httpx.AsyncClient,
        credentials: CredentialProvider,
        timeout_s: float = 10.0,
    ) -> None:
        self._url = url
        self._client = client
        self._credentials = credentials
        self._timeout = timeout_s

    async def tool_calls(self, session_id: str) -> Sequence[ToolCall]:
        try:
            response = await self._client.get(
                self._url,
                params={"session_id": session_id},
                headers=await self._credentials.headers(),
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise AdapterError(f"trace source unreachable: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise AdapterError(f"trace source returned HTTP {response.status_code}")
        try:
            body = response.json()
            calls = _CALLS.validate_python(body.get("tool_calls", []))
        except (ValueError, AttributeError, ValidationError) as exc:
            raise AdapterError("trace source reply violates the contract", retryable=False) from exc
        return calls[:MAX_TOOL_CALLS]


def _key(call: ToolCall) -> tuple[str, str, str | None, str]:
    return (
        call.name,
        call.status.value,
        call.approval_id,
        json.dumps(call.arguments, sort_keys=True, default=str),
    )


def merge_trace(response: TargetResponse, traced: Sequence[ToolCall]) -> TargetResponse:
    """Union of self-reported and traced calls; flags the response as externally traced."""
    seen = {_key(c) for c in response.tool_calls}
    extra = [c for c in traced if _key(c) not in seen]
    return response.model_copy(
        update={"tool_calls": (*response.tool_calls, *extra), "trace_source": "external"}
    )
