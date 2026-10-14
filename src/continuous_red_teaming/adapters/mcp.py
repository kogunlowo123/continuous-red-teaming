"""MCP server adapter, using the official ``mcp`` client over streamable HTTP.

The agent under test exposes a task tool (default ``run_task``) that accepts
the invocation payload. Its structured content must follow the agent reply
contract; a tool that only returns text is treated as output with no tool
calls. A session is opened per probe so concurrent probes never share MCP
session state and every task group is entered and exited in the same task.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import httpx2
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import TextContent

from continuous_red_teaming.adapters.base import (
    CredentialProvider,
    invocation_payload,
    parse_reply,
)
from continuous_red_teaming.domain.errors import AdapterError
from continuous_red_teaming.domain.models import ProbeInvocation, TargetResponse

TransportFactory = Callable[[], httpx2.AsyncBaseTransport]


class McpAgentAdapter:
    def __init__(
        self,
        endpoint: str,
        *,
        tool: str,
        credentials: CredentialProvider,
        timeout_s: float = 30.0,
        transport_factory: TransportFactory | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._tool = tool
        self._credentials = credentials
        self._timeout = timeout_s
        self._transport_factory = transport_factory

    async def invoke(self, invocation: ProbeInvocation) -> TargetResponse:
        headers = await self._credentials.headers()
        transport = self._transport_factory() if self._transport_factory else None
        started = time.perf_counter()
        try:
            async with (
                httpx2.AsyncClient(
                    headers=headers, timeout=self._timeout, transport=transport
                ) as http,
                Client(
                    streamable_http_client(self._endpoint, http_client=http),
                    read_timeout_seconds=self._timeout,
                    cache=None,
                ) as session,
            ):
                result = await session.call_tool(self._tool, invocation_payload(invocation))
        except Exception as exc:
            # SDK boundary: transport, protocol and task-group errors all mean
            # the probe could not be delivered; they never escape as crashes.
            raise AdapterError(f"MCP call failed: {type(exc).__name__}") from exc
        latency_ms = (time.perf_counter() - started) * 1000
        if result.is_error:
            raise AdapterError(f"MCP tool {self._tool} returned an error", retryable=False)
        if isinstance(result.structured_content, dict):
            return parse_reply(
                result.structured_content, latency_ms=latency_ms, trace_source="self-reported"
            )
        text = "\n".join(c.text for c in result.content if isinstance(c, TextContent))
        return parse_reply({"output": text}, latency_ms=latency_ms, trace_source="self-reported")
