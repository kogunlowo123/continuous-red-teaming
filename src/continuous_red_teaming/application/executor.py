"""Probe execution: bounded concurrency, timeouts, retries, trace merge, judging.

Failure handling is explicit and conservative:

* a probe the target could not answer is an ``error``, never a ``pass``;
* if an independent trace source is registered but unreachable, the probe is
  an ``error`` (its tool calls cannot be verified);
* after ``abort_after_consecutive_errors`` errors in a row the remaining
  probes are not sent: the target is down and hammering it proves nothing.
  The gate treats a category with too many errors as insufficient evidence.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Sequence

from opentelemetry import trace

from continuous_red_teaming.adapters.traces import merge_trace
from continuous_red_teaming.domain.errors import AdapterError, DependencyUnavailableError
from continuous_red_teaming.domain.models import (
    Probe,
    ProbeEvidence,
    ProbeOutcome,
    ProbeResult,
    TargetResponse,
    ToolCallRecord,
)
from continuous_red_teaming.domain.ports import TargetAdapter, TraceSource
from continuous_red_teaming.judges.panel import JudgePanel
from continuous_red_teaming.observability.metrics import RedTeamMetrics

EXCERPT_CHARS = 1000
tracer = trace.get_tracer("continuous_red_teaming.executor")


def evidence_of(response: TargetResponse) -> ProbeEvidence:
    return ProbeEvidence(
        response_status=response.status,
        output_digest="sha256:" + hashlib.sha256(response.output.encode()).hexdigest(),
        output_excerpt=response.output[:EXCERPT_CHARS],
        tool_calls=tuple(
            ToolCallRecord(name=c.name, status=c.status, approval_id=c.approval_id)
            for c in response.tool_calls
        ),
        latency_ms=response.latency_ms,
        trace_source=response.trace_source,
    )


class ProbeExecutor:
    def __init__(
        self,
        panel: JudgePanel,
        *,
        metrics: RedTeamMetrics,
        concurrency: int = 8,
        retries: int = 1,
        abort_after_consecutive_errors: int = 20,
    ) -> None:
        if concurrency < 1 or retries < 0 or abort_after_consecutive_errors < 1:
            raise ValueError("invalid executor limits")
        self._panel = panel
        self._metrics = metrics
        self._concurrency = concurrency
        self._retries = retries
        self._abort_after = abort_after_consecutive_errors

    async def execute(
        self,
        run_id: str,
        probes: Sequence[Probe],
        adapter: TargetAdapter,
        *,
        trace_source: TraceSource | None = None,
        timeout_s: float = 30.0,
        target_kind: str = "http",
    ) -> list[ProbeResult]:
        semaphore = asyncio.Semaphore(self._concurrency)
        state = {"consecutive_errors": 0}

        def failed(probe: Probe, message: str, attempts: int) -> ProbeResult:
            state["consecutive_errors"] += 1
            self._metrics.probes.labels(probe.category.value, ProbeOutcome.ERROR.value).inc()
            return ProbeResult(
                run_id=run_id,
                probe_id=probe.probe_id,
                scenario_id=probe.scenario_id,
                category=probe.category,
                severity=probe.severity,
                outcome=ProbeOutcome.ERROR,
                error=message,
                attempts=attempts,
            )

        async def invoke(probe: Probe) -> tuple[TargetResponse | None, str, int]:
            attempts, message = 0, ""
            while attempts <= self._retries:
                attempts += 1
                try:
                    async with asyncio.timeout(timeout_s):
                        return await adapter.invoke(probe.invocation), "", attempts
                except TimeoutError:
                    message = f"target did not answer within {timeout_s:g}s"
                except AdapterError as exc:
                    message = exc.message
                    if not exc.retryable:
                        break
                except DependencyUnavailableError as exc:
                    return None, exc.message, attempts
            return None, message, attempts

        async def one(probe: Probe) -> ProbeResult:
            async with semaphore:
                if state["consecutive_errors"] >= self._abort_after:
                    return failed(
                        probe,
                        f"not sent: {self._abort_after} consecutive target errors",
                        attempts=0,
                    )
                with tracer.start_as_current_span("probe") as span:
                    span.set_attribute("crt.scenario", probe.scenario_id)
                    span.set_attribute("crt.category", probe.category.value)
                    response, message, attempts = await invoke(probe)
                    if response is None:
                        span.set_attribute("crt.outcome", "error")
                        return failed(probe, message, attempts)
                    if trace_source is not None:
                        try:
                            traced = await trace_source.tool_calls(probe.invocation.session_id)
                        except (AdapterError, DependencyUnavailableError) as exc:
                            return failed(probe, f"trace unavailable: {exc.message}", attempts)
                        response = merge_trace(response, traced)
                    outcome, verdicts = await self._panel.assess(probe, response)
                    span.set_attribute("crt.outcome", outcome.value)
                state["consecutive_errors"] = 0
                self._metrics.probes.labels(probe.category.value, outcome.value).inc()
                self._metrics.probe_latency.labels(target_kind).observe(response.latency_ms / 1000)
                return ProbeResult(
                    run_id=run_id,
                    probe_id=probe.probe_id,
                    scenario_id=probe.scenario_id,
                    category=probe.category,
                    severity=probe.severity,
                    outcome=outcome,
                    verdicts=verdicts,
                    evidence=evidence_of(response),
                    attempts=attempts,
                )

        return list(await asyncio.gather(*(one(p) for p in probes)))
