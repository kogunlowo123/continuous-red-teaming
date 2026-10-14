"""A2A agent adapter: JSON-RPC 2.0 ``message/send`` (A2A protocol 0.3).

The probe task travels as a text part and the context documents as a data
part. The agent's answer is read from the returned Message, or from the Task
(status message and artifacts). Tool calls are reported in a data part with
the agent reply contract (``{"tool_calls": [...]}``). Non-terminal tasks are
polled with ``tasks/get`` until they settle or the probe times out.

Task state mapping: completed -> completed; input-required / auth-required
-> require_approval; rejected -> refused; failed / canceled -> error.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from continuous_red_teaming.adapters.base import CredentialProvider, parse_reply
from continuous_red_teaming.domain.errors import AdapterError
from continuous_red_teaming.domain.models import ProbeInvocation, ResponseStatus, TargetResponse

STATE_MAP = {
    "completed": ResponseStatus.COMPLETED,
    "input-required": ResponseStatus.REQUIRE_APPROVAL,
    "auth-required": ResponseStatus.REQUIRE_APPROVAL,
    "rejected": ResponseStatus.REFUSED,
    "failed": ResponseStatus.ERROR,
    "canceled": ResponseStatus.ERROR,
}
PENDING_STATES = frozenset({"submitted", "working", "unknown"})

Sleep = Callable[[float], Awaitable[None]]


def message_send(invocation: ProbeInvocation) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": f"probe-{invocation.session_id}",
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "role": "user",
                "messageId": invocation.session_id,
                "contextId": invocation.session_id,
                "parts": [
                    {"kind": "text", "text": invocation.task},
                    {
                        "kind": "data",
                        "data": {
                            "context": [d.model_dump(mode="json") for d in invocation.context]
                        },
                    },
                ],
            },
            "configuration": {"blocking": True, "acceptedOutputModes": ["text", "data"]},
        },
    }


def _parts(result: dict[str, Any]) -> list[dict[str, Any]]:
    parts: list[Any] = []
    if result.get("kind") == "message":
        parts.extend(result.get("parts") or [])
    else:
        status = result.get("status") or {}
        message = status.get("message") if isinstance(status, dict) else None
        if isinstance(message, dict):
            parts.extend(message.get("parts") or [])
        for artifact in result.get("artifacts") or []:
            if isinstance(artifact, dict):
                parts.extend(artifact.get("parts") or [])
    return [p for p in parts if isinstance(p, dict)]


def reply_from_result(result: dict[str, Any]) -> dict[str, Any]:
    parts = _parts(result)
    texts = [str(p.get("text", "")) for p in parts if p.get("kind") == "text"]
    reply: dict[str, Any] = {}
    for part in parts:
        data = part.get("data") if part.get("kind") == "data" else None
        if isinstance(data, dict) and ({"tool_calls", "output", "status"} & set(data)):
            reply.update(data)
    reply.setdefault("output", "\n".join(t for t in texts if t))
    if "status" not in reply and result.get("kind") == "task":
        state = str((result.get("status") or {}).get("state", "completed"))
        mapped = STATE_MAP.get(state)
        if mapped is None:
            raise AdapterError(f"A2A task ended in unexpected state {state!r}", retryable=False)
        reply["status"] = mapped.value
    reply.setdefault("status", ResponseStatus.COMPLETED.value)
    return reply


class A2AAgentAdapter:
    def __init__(
        self,
        endpoint: str,
        *,
        client: httpx.AsyncClient,
        credentials: CredentialProvider,
        timeout_s: float = 30.0,
        poll_interval_s: float = 0.5,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._endpoint = endpoint
        self._client = client
        self._credentials = credentials
        self._timeout = timeout_s
        self._poll = poll_interval_s
        self._sleep = sleep

    async def _call(self, body: dict[str, Any]) -> dict[str, Any]:
        headers = {"Accept": "application/json", **(await self._credentials.headers())}
        try:
            response = await self._client.post(
                self._endpoint, json=body, headers=headers, timeout=self._timeout
            )
        except httpx.HTTPError as exc:
            raise AdapterError(f"A2A agent unreachable: {type(exc).__name__}") from exc
        if response.status_code >= 500:
            raise AdapterError(f"A2A agent returned HTTP {response.status_code}")
        if response.status_code >= 400:
            raise AdapterError(f"A2A agent returned HTTP {response.status_code}", retryable=False)
        try:
            envelope = response.json()
        except ValueError as exc:
            raise AdapterError("A2A reply is not JSON", retryable=False) from exc
        if not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0":
            raise AdapterError("A2A reply is not a JSON-RPC 2.0 response", retryable=False)
        if "error" in envelope:
            error = envelope["error"] if isinstance(envelope["error"], dict) else {}
            raise AdapterError(
                f"A2A error {error.get('code')}: {error.get('message', '')}", retryable=False
            )
        result = envelope.get("result")
        if not isinstance(result, dict):
            raise AdapterError("A2A reply carries no result object", retryable=False)
        return result

    async def invoke(self, invocation: ProbeInvocation) -> TargetResponse:
        started = time.perf_counter()
        result = await self._call(message_send(invocation))
        while result.get("kind") == "task" and (
            str((result.get("status") or {}).get("state")) in PENDING_STATES
        ):
            if time.perf_counter() - started > self._timeout:
                raise AdapterError("A2A task did not settle before the probe timeout")
            await self._sleep(self._poll)
            result = await self._call(
                {
                    "jsonrpc": "2.0",
                    "id": f"poll-{invocation.session_id}",
                    "method": "tasks/get",
                    "params": {"id": result.get("id")},
                }
            )
        latency_ms = (time.perf_counter() - started) * 1000
        return parse_reply(
            reply_from_result(result), latency_ms=latency_ms, trace_source="self-reported"
        )
