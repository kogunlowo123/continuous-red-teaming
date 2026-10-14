"""Shared fixtures: in-process identity providers, a platform wired to SQLite, and an app."""

from __future__ import annotations

import os
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from continuous_red_teaming.api.app import create_app
from continuous_red_teaming.config import Settings
from continuous_red_teaming.domain.models import (
    ReferenceProfile,
    Severity,
    TargetKind,
    TargetRegistration,
)
from continuous_red_teaming.runtime.container import Container, build_container
from continuous_red_teaming.security.auth import PrincipalKind, TrustedIssuer
from continuous_red_teaming.security.jwks import StaticJwks

ROOT = Path(__file__).resolve().parents[1]
ENTERPRISE_ISSUER = "https://login.corp.test/tenant"
CI_ISSUER = "https://ci.corp.test"
FABRIC_ISSUER = "https://identity.corp.test"
AUDIENCE = "continuous-red-teaming"
CI_SUBJECT = "repo:corp/agents:ref:refs/heads/main"
HARDENED = ReferenceProfile()
LEAKY = ReferenceProfile(
    marker_leak_rate=0.3, secret_echo_rate=0.1, forbidden_tool_rate=0.2, approval_bypass_rate=0.25
)


@dataclass
class FakeIdp:
    """Minimal OIDC issuer: ES256 keypair plus JWKS."""

    issuer: str
    kid: str = "k1"
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}

    def mint(self, *, sub: str, aud: str = AUDIENCE, ttl: int = 300, **extra: Any) -> str:
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl}
        claims.update(extra)
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})


@dataclass
class FakeClock:
    current: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


@pytest.fixture
def enterprise_idp() -> FakeIdp:
    return FakeIdp(ENTERPRISE_ISSUER)


@pytest.fixture
def ci_idp() -> FakeIdp:
    return FakeIdp(CI_ISSUER, kid="ci-1")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def trusted_issuers() -> list[TrustedIssuer]:
    return [
        TrustedIssuer(
            issuer=ENTERPRISE_ISSUER,
            jwks_url="https://login.corp.test/tenant/jwks",
            audience=AUDIENCE,
            kind=PrincipalKind.USER,
        ),
        TrustedIssuer(
            issuer=CI_ISSUER,
            jwks_url="https://ci.corp.test/jwks",
            audience=AUDIENCE,
            kind=PrincipalKind.PIPELINE,
            default_roles=("release-pipeline",),
            subject_patterns=("repo:corp/agents:*",),
        ),
    ]


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    db = os.environ.get("CRT_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'crt.db'}")
    values: dict[str, Any] = {
        "environment": "test",
        "public_url": "https://redteam.corp.test",
        "database_url": db,
        "dev_ephemeral_keys": True,
        "audit_log_path": tmp_path / "audit.jsonl",
        "suites_dir": ROOT / "suites",
        "gate_policy_file": ROOT / "policies" / "release-gate.yaml",
        "decision_policy_file": ROOT / "policies" / "release-decision.yaml",
        "access_policy_file": ROOT / "policies" / "platform-access.yaml",
        "target_tool_policy_file": ROOT / "policies" / "target-tool-policy.yaml",
        "trusted_issuers": trusted_issuers(),
        "target_allowed_hosts": ["agents.corp.test", "*.agents.corp.test"],
        "allow_reference_targets": True,
        "mcp_allowed_hosts": ["testserver", "redteam.corp.test"],
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


def resolvers(enterprise: FakeIdp, ci: FakeIdp) -> dict[str, StaticJwks]:
    return {
        ENTERPRISE_ISSUER: StaticJwks(enterprise.jwks()),
        CI_ISSUER: StaticJwks(ci.jwks()),
    }


@pytest.fixture
async def container(
    settings: Settings, enterprise_idp: FakeIdp, ci_idp: FakeIdp, clock: FakeClock
) -> AsyncIterator[Container]:
    built = await build_container(
        settings, issuer_resolvers=resolvers(enterprise_idp, ci_idp), clock=clock
    )
    yield built
    await built.aclose()


def user_headers(idp: FakeIdp, *roles: str, sub: str = "alice@corp.test") -> dict[str, str]:
    return {"Authorization": f"Bearer {idp.mint(sub=sub, roles=list(roles))}"}


def pipeline_headers(idp: FakeIdp, sub: str = CI_SUBJECT) -> dict[str, str]:
    return {"Authorization": f"Bearer {idp.mint(sub=sub)}"}


def reference_registration(
    name: str = "support-agent",
    profile: ReferenceProfile = HARDENED,
    *,
    risk: Severity = Severity.MODERATE,
) -> TargetRegistration:
    return TargetRegistration(
        name=name,
        description="Reference agent with a configured weakness profile",
        kind=TargetKind.REFERENCE,
        reference_profile=profile,
        risk=risk,
        owner="agent-platform-team",
    )


@pytest.fixture
def client(
    settings: Settings, enterprise_idp: FakeIdp, ci_idp: FakeIdp, clock: FakeClock
) -> Iterator[TestClient]:
    """App whose container is built inside the app's own event loop by its lifespan."""

    async def factory() -> Container:
        return await build_container(
            settings, issuer_resolvers=resolvers(enterprise_idp, ci_idp), clock=clock
        )

    with TestClient(create_app(factory, mcp_allowed_hosts=["testserver"])) as test_client:
        yield test_client
