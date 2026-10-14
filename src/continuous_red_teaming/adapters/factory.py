"""Builds the adapter and optional trace source for a registered target."""

from __future__ import annotations

from collections.abc import Mapping

import httpx
from agentic_core.policy import PolicyEngine

from continuous_red_teaming.adapters.a2a import A2AAgentAdapter
from continuous_red_teaming.adapters.base import (
    CredentialProvider,
    EnvBearer,
    FabricBearer,
    NoCredentials,
)
from continuous_red_teaming.adapters.http import HttpAgentAdapter
from continuous_red_teaming.adapters.mcp import McpAgentAdapter, TransportFactory
from continuous_red_teaming.adapters.reference import ReferenceAgent
from continuous_red_teaming.adapters.traces import HttpTraceSource
from continuous_red_teaming.domain.errors import TargetPolicyError
from continuous_red_teaming.domain.models import Target, TargetAuth, TargetKind
from continuous_red_teaming.domain.ports import TargetAdapter, TraceSource
from continuous_red_teaming.integrations.identity_fabric import IdentityFabricClient
from continuous_red_teaming.security.egress import EgressPolicy


class AdapterFactory:
    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        egress: EgressPolicy,
        reference_tool_policy: PolicyEngine,
        allow_reference_targets: bool,
        fabric: IdentityFabricClient | None = None,
        env: Mapping[str, str] | None = None,
        mcp_transport_factory: TransportFactory | None = None,
    ) -> None:
        self._http = http
        self._egress = egress
        self._reference_policy = reference_tool_policy
        self._allow_reference = allow_reference_targets
        self._fabric = fabric
        self._env = env
        self._mcp_transport_factory = mcp_transport_factory

    def validate(self, target: Target) -> None:
        """Registration-time checks; the same checks run again before every run."""
        if target.kind is TargetKind.REFERENCE:
            if not self._allow_reference:
                raise TargetPolicyError("reference targets are disabled on this deployment")
            return
        if target.endpoint is None:  # pragma: no cover - enforced by the model
            raise TargetPolicyError("target has no endpoint")
        self._egress.check(target.endpoint)
        if target.trace_endpoint is not None:
            self._egress.check(target.trace_endpoint)
        if target.auth is TargetAuth.FABRIC and self._fabric is None:
            raise TargetPolicyError("fabric auth needs CRT_FABRIC_URL to be configured")

    def credentials(self, target: Target) -> CredentialProvider:
        match target.auth:
            case TargetAuth.ENV_BEARER:
                if target.auth_env is None:  # pragma: no cover - enforced by the model
                    raise TargetPolicyError("env_bearer auth without auth_env")
                return EnvBearer(target.auth_env, self._env)
            case TargetAuth.FABRIC:
                if self._fabric is None:
                    raise TargetPolicyError("fabric auth needs CRT_FABRIC_URL to be configured")
                return FabricBearer(self._fabric)
        return NoCredentials()

    def adapter(self, target: Target) -> TargetAdapter:
        self.validate(target)
        if target.kind is TargetKind.REFERENCE:
            if target.reference_profile is None:  # pragma: no cover - enforced by the model
                raise TargetPolicyError("reference target without a profile")
            return ReferenceAgent(target.reference_profile, self._reference_policy)
        endpoint = str(target.endpoint)
        credentials = self.credentials(target)
        if target.kind is TargetKind.MCP:
            return McpAgentAdapter(
                endpoint,
                tool=target.mcp_tool,
                credentials=credentials,
                timeout_s=target.timeout_s,
                transport_factory=self._mcp_transport_factory,
            )
        if target.kind is TargetKind.A2A:
            return A2AAgentAdapter(
                endpoint, client=self._http, credentials=credentials, timeout_s=target.timeout_s
            )
        return HttpAgentAdapter(
            endpoint, client=self._http, credentials=credentials, timeout_s=target.timeout_s
        )

    def trace_source(self, target: Target) -> TraceSource | None:
        if target.trace_endpoint is None:
            return None
        return HttpTraceSource(
            target.trace_endpoint, client=self._http, credentials=self.credentials(target)
        )
