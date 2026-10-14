"""HTTP agent endpoint adapter (JSON wire contract in adapters.base)."""

from __future__ import annotations

import time

import httpx

from continuous_red_teaming.adapters.base import (
    CredentialProvider,
    invocation_payload,
    parse_reply,
)
from continuous_red_teaming.domain.errors import AdapterError
from continuous_red_teaming.domain.models import ProbeInvocation, TargetResponse

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class HttpAgentAdapter:
    def __init__(
        self,
        endpoint: str,
        *,
        client: httpx.AsyncClient,
        credentials: CredentialProvider,
        timeout_s: float = 30.0,
    ) -> None:
        self._endpoint = endpoint
        self._client = client
        self._credentials = credentials
        self._timeout = timeout_s

    async def invoke(self, invocation: ProbeInvocation) -> TargetResponse:
        headers = {"Accept": "application/json", **(await self._credentials.headers())}
        started = time.perf_counter()
        try:
            response = await self._client.post(
                self._endpoint,
                json=invocation_payload(invocation),
                headers=headers,
                timeout=self._timeout,
            )
        except httpx.TimeoutException as exc:
            raise AdapterError("target timed out") from exc
        except httpx.HTTPError as exc:
            raise AdapterError(f"target unreachable: {type(exc).__name__}") from exc
        latency_ms = (time.perf_counter() - started) * 1000
        if response.status_code >= 400:
            raise AdapterError(
                f"target returned HTTP {response.status_code}",
                retryable=response.status_code in RETRYABLE_STATUS,
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise AdapterError("target reply is not JSON", retryable=False) from exc
        return parse_reply(payload, latency_ms=latency_ms, trace_source="self-reported")
