"""Dependency container built once per process from Settings (composition root)."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass

import httpx
from agentic_core.audit import AuditLog, JsonlAuditSink
from agentic_core.models.factory import ProvidersConfig, build_providers
from agentic_core.models.router import ModelRouter
from agentic_core.observability import ModelTelemetryObserver
from agentic_core.policy import PolicyEngine, PolicySet
from agentic_core.security import ContentGuard
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.ext.asyncio import AsyncEngine

from continuous_red_teaming.adapters.factory import AdapterFactory
from continuous_red_teaming.adapters.mcp import TransportFactory
from continuous_red_teaming.application.scheduler import RunScheduler
from continuous_red_teaming.application.service import RedTeamService
from continuous_red_teaming.config import Settings
from continuous_red_teaming.domain.ports import Clock
from continuous_red_teaming.domain.suites import SuiteCatalog
from continuous_red_teaming.gate.evaluator import ReleaseGate
from continuous_red_teaming.gate.policy import GatePolicy
from continuous_red_teaming.gate.report import ReportSigner
from continuous_red_teaming.infrastructure.database import (
    SqlDecisionRepository,
    SqlRunRepository,
    SqlTargetRepository,
    SystemClock,
    create_schema,
    make_engine,
)
from continuous_red_teaming.integrations.identity_fabric import IdentityFabricClient
from continuous_red_teaming.judges.llm import LlmRubricJudge
from continuous_red_teaming.observability.metrics import RedTeamMetrics
from continuous_red_teaming.security.access import AccessController
from continuous_red_teaming.security.auth import Authenticator
from continuous_red_teaming.security.egress import EgressPolicy
from continuous_red_teaming.security.jwks import KeyResolver, RemoteJwks


@dataclass
class Container:
    settings: Settings
    service: RedTeamService
    scheduler: RunScheduler
    authenticator: Authenticator
    access: AccessController
    audit: AuditLog
    metrics: RedTeamMetrics
    engine: AsyncEngine
    http: httpx.AsyncClient
    router: ModelRouter | None = None

    async def aclose(self) -> None:
        await self.scheduler.aclose()
        if self.router is not None:
            await self.router.aclose()
        await self.http.aclose()
        await self.engine.dispose()


def _signing_key(settings: Settings) -> tuple[Ed25519PrivateKey, str]:
    if settings.audit_key_file is None:
        return Ed25519PrivateKey.generate(), "report-ephemeral"
    key = serialization.load_pem_private_key(settings.audit_key_file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("audit key must be Ed25519")
    return key, settings.audit_key_file.stem


def _retired(settings: Settings) -> dict[str, Ed25519PublicKey]:
    return {
        kid: Ed25519PublicKey.from_public_bytes(base64.b64decode(raw))
        for kid, raw in settings.retired_report_keys.items()
    }


def _llm_judge(
    settings: Settings, env: Mapping[str, str] | None, transport: httpx.AsyncBaseTransport | None
) -> tuple[LlmRubricJudge | None, ModelRouter | None]:
    if settings.providers_file is None:
        return None, None
    config = ProvidersConfig.from_file(settings.providers_file, env=env)
    router = ModelRouter(
        build_providers(config, env=env, transport=transport),
        observers=[ModelTelemetryObserver()],
    )
    judge = LlmRubricJudge(router, ContentGuard(), classification=settings.llm_judge_classification)
    return judge, router


async def build_container(
    settings: Settings,
    *,
    issuer_resolvers: Mapping[str, KeyResolver] | None = None,
    clock: Clock | None = None,
    http: httpx.AsyncClient | None = None,
    env: Mapping[str, str] | None = None,
    model_transport: httpx.AsyncBaseTransport | None = None,
    mcp_transport_factory: TransportFactory | None = None,
) -> Container:
    clock = clock or SystemClock()
    http = http or httpx.AsyncClient(timeout=httpx.Timeout(30.0), follow_redirects=False)

    resolvers: dict[str, KeyResolver] = dict(issuer_resolvers or {})
    for issuer in settings.trusted_issuers:
        resolvers.setdefault(issuer.issuer, RemoteJwks(issuer.jwks_url, client=http))

    engine = make_engine(settings.database_url)
    await create_schema(engine)

    key, key_id = _signing_key(settings)
    audit = AuditLog(JsonlAuditSink(settings.audit_log_path), key, key_id=key_id)
    metrics = RedTeamMetrics()

    fabric = (
        IdentityFabricClient(
            settings.fabric_url,
            client=http,
            clock=clock,
            client_id=settings.fabric_client_id,
            workload_token_file=settings.fabric_workload_token_file,
            scope=settings.fabric_scope,
        )
        if settings.fabric_url
        else None
    )
    tool_policy = PolicyEngine(PolicySet.from_file(settings.target_tool_policy_file))
    adapters = AdapterFactory(
        http=http,
        egress=EgressPolicy(
            settings.target_allowed_hosts, allow_insecure=settings.allow_insecure_targets
        ),
        reference_tool_policy=tool_policy,
        allow_reference_targets=settings.allow_reference_targets,
        fabric=fabric,
        env=env,
        mcp_transport_factory=mcp_transport_factory,
    )
    llm_judge, router = _llm_judge(settings, env, model_transport)
    service = RedTeamService(
        suites=SuiteCatalog.from_directory(settings.suites_dir),
        targets=SqlTargetRepository(engine),
        runs=SqlRunRepository(engine),
        decisions=SqlDecisionRepository(engine),
        adapters=adapters,
        gate=ReleaseGate(
            GatePolicy.from_file(settings.gate_policy_file),
            PolicyEngine(PolicySet.from_file(settings.decision_policy_file)),
        ),
        signer=ReportSigner(key, key_id, retired=_retired(settings)),
        audit=audit,
        clock=clock,
        metrics=metrics,
        default_tool_policy=tool_policy,
        llm_judge=llm_judge,
        max_probes_per_run=settings.max_probes_per_run,
        concurrency=settings.probe_concurrency,
        abort_after_consecutive_errors=settings.abort_after_consecutive_errors,
    )
    return Container(
        settings=settings,
        service=service,
        scheduler=RunScheduler(service, max_active_runs=settings.max_active_runs),
        authenticator=Authenticator(
            settings.trusted_issuers,
            resolvers,
            clock=clock,
            fabric_issuer=settings.fabric_issuer,
        ),
        access=AccessController(
            PolicyEngine(PolicySet.from_file(settings.access_policy_file)), audit, fabric, metrics
        ),
        audit=audit,
        metrics=metrics,
        engine=engine,
        http=http,
        router=router,
    )
