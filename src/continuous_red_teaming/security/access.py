"""Authorization of platform actions.

People and pipelines are authorized by the local agentic-core PolicyEngine
(``policies/platform-access.yaml``: roles, deny-overrides, default deny).
Agents are authorized by the identity fabric's ``/v1/authorize``; when no
fabric is configured, agent tokens are refused (never "allow all").
Approving a release is a human decision and is refused for agents outright.
Every refusal is written to the signed audit chain.
"""

from __future__ import annotations

from typing import Any

from agentic_core.audit import AuditLog
from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject

from continuous_red_teaming.domain.errors import ApprovalRequiredError, ForbiddenError
from continuous_red_teaming.integrations.identity_fabric import IdentityFabricClient
from continuous_red_teaming.observability.metrics import RedTeamMetrics
from continuous_red_teaming.security.auth import Principal


class Action:
    SUITES_READ = "redteam.suites:read"
    TARGETS_READ = "redteam.targets:read"
    TARGETS_REGISTER = "redteam.targets:register"
    RUNS_READ = "redteam.runs:read"
    RUNS_START = "redteam.runs:start"
    GATE_READ = "redteam.gate:read"
    GATE_EVALUATE = "redteam.gate:evaluate"
    GATE_APPROVE = "redteam.gate:approve"
    JUDGES_CALIBRATE = "redteam.judges:calibrate"


HUMAN_ONLY = frozenset({Action.GATE_APPROVE, Action.TARGETS_REGISTER, Action.JUDGES_CALIBRATE})


class AccessController:
    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditLog,
        fabric: IdentityFabricClient | None,
        metrics: RedTeamMetrics,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._fabric = fabric
        self._metrics = metrics

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    async def _refuse(
        self, principal: Principal, action: str, resource: str, reason: str, rules: tuple[str, ...]
    ) -> None:
        self._metrics.access_denied.labels(action).inc()
        await self._audit.record(
            actor=principal.subject,
            action="access.denied",
            resource=resource,
            outcome="deny",
            details={"requested": action, "reason": reason, "rules": list(rules)},
        )

    async def authorize(
        self,
        principal: Principal,
        action: str,
        *,
        resource_type: str = "redteam",
        resource_id: str = "*",
        attributes: dict[str, Any] | None = None,
    ) -> None:
        resource = f"{resource_type}:{resource_id}"
        if principal.is_agent:
            await self._authorize_agent(principal, action, resource_type, resource_id, attributes)
            return
        decision = self._policy.evaluate(
            PolicyRequest(
                subject=Subject(
                    id=principal.subject, kind=principal.kind.value, roles=principal.roles
                ),
                action=action,
                resource=Resource(type=resource_type, id=resource_id, attributes=attributes or {}),
            )
        )
        if decision.decision is Decision.ALLOW:
            return
        await self._refuse(principal, action, resource, decision.reason, decision.matched_rules)
        if decision.decision is Decision.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(f"{action} requires human approval")
        raise ForbiddenError(f"{action} is not permitted: {decision.reason}")

    async def _authorize_agent(
        self,
        principal: Principal,
        action: str,
        resource_type: str,
        resource_id: str,
        attributes: dict[str, Any] | None,
    ) -> None:
        resource = f"{resource_type}:{resource_id}"
        if action in HUMAN_ONLY:
            await self._refuse(principal, action, resource, "human-only action", ())
            raise ForbiddenError(f"{action} must be performed by a person")
        if self._fabric is None:
            await self._refuse(principal, action, resource, "no identity fabric configured", ())
            raise ForbiddenError("agent credentials are not accepted without an identity fabric")
        decision = await self._fabric.authorize(
            principal.credential,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            attributes=attributes,
        )
        if decision.decision is Decision.ALLOW:
            return
        await self._refuse(principal, action, resource, decision.reason, decision.matched_rules)
        if decision.decision is Decision.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(f"{action} requires human approval")
        raise ForbiddenError(f"{action} denied by identity fabric: {decision.reason}")
