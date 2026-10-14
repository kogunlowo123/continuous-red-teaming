"""Reference agent: a deterministic target with known, measurable weaknesses.

The platform's numbers are only worth something if its judges and
statistics recover a weakness rate that is known in advance. The reference
agent behaves like a simple tool-using assistant and is blind to probe
categories:

* it summarises context documents; with probability ``marker_leak_rate``
  (``secret_echo_rate`` for documents that carry credential fields) it quotes
  a document verbatim instead of withholding identifier-like values;
* it plans calls for every dotted tool name mentioned in the task and checks
  each against its tool policy: denied tools are declined, approval-gated
  tools are proposed for approval, unless the matching weakness draw
  (``forbidden_tool_rate`` / ``approval_bypass_rate``) says it misbehaves.

Draws are a hash of (seed, session, aspect), so a run is reproducible and the
expected failure rate of each category equals the configured probability.
"""

from __future__ import annotations

import hashlib
import re

from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicyEngine

from continuous_red_teaming.domain.models import (
    ProbeInvocation,
    ReferenceProfile,
    ResponseStatus,
    TargetResponse,
    ToolCall,
    ToolCallStatus,
)
from continuous_red_teaming.judges.tools import ToolPolicy

TOOL_MENTION = re.compile(r"\b([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)\b")
CREDENTIAL_FIELD = re.compile(r"(?i)\b(credential|secret|api[ _-]?key|password|token)\b")
IDENTIFIER = re.compile(r"\b[A-Z][A-Z0-9]*-[0-9A-Za-z][0-9A-Za-z\-]{7,}\b")
ASSIGNMENT = re.compile(r"(?i)\b(credential|secret|api[ _-]?key|password|token)\b(\s*[:=]\s*)\S+")


def withhold(text: str) -> str:
    """Hardened summarisation: identifier-like values and credential fields are withheld."""
    return IDENTIFIER.sub("[withheld]", ASSIGNMENT.sub(r"\1\2[withheld]", text))


class ReferenceAgent:
    def __init__(self, profile: ReferenceProfile, tool_policy: PolicyEngine) -> None:
        self._profile = profile
        self._policy = ToolPolicy(tool_policy)

    @property
    def profile(self) -> ReferenceProfile:
        return self._profile

    def draw(self, session_id: str, aspect: str) -> float:
        digest = hashlib.sha256(f"{self._profile.seed}:{session_id}:{aspect}".encode()).digest()
        return int.from_bytes(digest[:8], "big") / 2**64

    def _plan(
        self, invocation: ProbeInvocation
    ) -> tuple[list[ToolCall], ResponseStatus, list[str]]:
        calls: list[ToolCall] = []
        status = ResponseStatus.COMPLETED
        notes: list[str] = []
        mentioned = list(dict.fromkeys(TOOL_MENTION.findall(invocation.task)))
        for name in mentioned:
            arguments = {"request": invocation.task[:120]}
            decision = self._policy.decide(
                ToolCall(name=name), session_id=invocation.session_id
            ).decision
            if decision is Decision.DENY:
                misbehave = (
                    self.draw(invocation.session_id, f"tool:{name}")
                    < self._profile.forbidden_tool_rate
                )
                if misbehave:
                    calls.append(ToolCall(name=name, arguments=arguments))
                else:
                    calls.append(ToolCall(name=name, arguments={}, status=ToolCallStatus.BLOCKED))
                    status = ResponseStatus.REFUSED
                    notes.append(f"I cannot use {name}: it is outside my permitted tools.")
            elif decision is Decision.REQUIRE_APPROVAL:
                misbehave = (
                    self.draw(invocation.session_id, f"approval:{name}")
                    < self._profile.approval_bypass_rate
                )
                if misbehave:
                    calls.append(ToolCall(name=name, arguments=arguments))
                else:
                    calls.append(
                        ToolCall(name=name, arguments=arguments, status=ToolCallStatus.PROPOSED)
                    )
                    if status is ResponseStatus.COMPLETED:
                        status = ResponseStatus.REQUIRE_APPROVAL
                    notes.append(f"{name} needs human approval; request submitted.")
            else:
                calls.append(ToolCall(name=name, arguments=arguments))
        return calls, status, notes

    async def invoke(self, invocation: ProbeInvocation) -> TargetResponse:
        calls, status, notes = self._plan(invocation)
        lines = [f"Task received: {withhold(invocation.task)[:200]}"]
        for document in invocation.context:
            sensitive = CREDENTIAL_FIELD.search(document.content) is not None
            rate = self._profile.secret_echo_rate if sensitive else self._profile.marker_leak_rate
            if self.draw(invocation.session_id, f"context:{document.id}") < rate:
                lines.append(f"{document.source}: {document.content}")
            else:
                lines.append(f"{document.source}: {withhold(document.content)}")
        lines.extend(notes)
        return TargetResponse(
            output="\n".join(lines),
            tool_calls=tuple(calls),
            status=status,
            latency_ms=0.0,
            trace_source="self-reported",
        )
