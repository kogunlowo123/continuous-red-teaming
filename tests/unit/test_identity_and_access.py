"""Authentication (OIDC issuers, fabric credentials), access control and the fabric client."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from agentic_core.audit import AuditLog, InMemoryAuditSink
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from continuous_red_teaming.domain.errors import (
    ApprovalRequiredError,
    DependencyUnavailableError,
    ForbiddenError,
    UnauthorizedError,
)
from continuous_red_teaming.integrations.identity_fabric import IdentityFabricClient
from continuous_red_teaming.observability.metrics import RedTeamMetrics
from continuous_red_teaming.security.access import AccessController, Action
from continuous_red_teaming.security.auth import (
    Authenticator,
    Principal,
    PrincipalKind,
    bearer_token,
)
from continuous_red_teaming.security.jwks import RemoteJwks, StaticJwks, unverified_claims
from tests.conftest import (
    AUDIENCE,
    CI_SUBJECT,
    FABRIC_ISSUER,
    ROOT,
    FakeClock,
    FakeIdp,
    resolvers,
    trusted_issuers,
)


def authenticator(enterprise: FakeIdp, ci: FakeIdp, clock: FakeClock) -> Authenticator:
    return Authenticator(
        trusted_issuers(), resolvers(enterprise, ci), clock=clock, fabric_issuer=FABRIC_ISSUER
    )


async def test_user_and_pipeline_tokens(
    enterprise_idp: FakeIdp, ci_idp: FakeIdp, clock: FakeClock
) -> None:
    auth = authenticator(enterprise_idp, ci_idp, clock)
    user = await auth.authenticate(
        f"Bearer {enterprise_idp.mint(sub='alice@corp.test', roles=['redteam-operator', 7])}"
    )
    assert user.kind is PrincipalKind.USER
    assert user.roles == {"redteam-operator"}
    assert "credential" not in repr(user)
    pipeline = await auth.authenticate(f"Bearer {ci_idp.mint(sub=CI_SUBJECT)}")
    assert pipeline.kind is PrincipalKind.PIPELINE
    assert pipeline.roles == {"release-pipeline"}
    no_roles = await auth.authenticate(
        f"Bearer {enterprise_idp.mint(sub='bob@corp.test', roles='not-a-list')}"
    )
    assert no_roles.roles == frozenset()


@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda e, c: None, "bearer token required"),
        (lambda e, c: "Basic abc", "bearer token required"),
        (lambda e, c: "Bearer ", "bearer token required"),
        (lambda e, c: "Bearer not-a-jwt", "malformed"),
        (lambda e, c: f"Bearer {c.mint(sub='repo:other/repo:ref:refs/heads/main')}", "subject"),
        (lambda e, c: f"Bearer {e.mint(sub='a', aud='other')}", "InvalidAudience"),
        (lambda e, c: f"Bearer {e.mint(sub='a', ttl=-120)}", "expired"),
        (lambda e, c: f"Bearer {e.mint(sub='a', nbf=4102444800)}", "not yet valid"),
        (lambda e, c: f"Bearer {FakeIdp('https://evil.test').mint(sub='a')}", "not trusted"),
        (lambda e, c: f"Bearer {FakeIdp(e.issuer).mint(sub='a')}", "InvalidSignature"),
        (lambda e, c: f"Bearer {FakeIdp(e.issuer, kid='zz').mint(sub='a')}", "unknown signing key"),
    ],
)
async def test_rejected_tokens(
    enterprise_idp: FakeIdp, ci_idp: FakeIdp, clock: FakeClock, make: Any, message: str
) -> None:
    auth = authenticator(enterprise_idp, ci_idp, clock)
    with pytest.raises(UnauthorizedError, match=message):
        await auth.authenticate(make(enterprise_idp, ci_idp))


async def test_fabric_tokens_become_unverified_agent_principals(
    enterprise_idp: FakeIdp, ci_idp: FakeIdp, clock: FakeClock
) -> None:
    auth = authenticator(enterprise_idp, ci_idp, clock)
    fabric = FakeIdp(FABRIC_ISSUER)
    agent = await auth.authenticate(f"Bearer {fabric.mint(sub='spiffe://corp/agent/a/b')}")
    assert agent.is_agent
    assert agent.credential
    with pytest.raises(UnauthorizedError, match="no subject"):
        await auth.authenticate(f"Bearer {fabric.mint(sub='')}")


def test_authenticator_needs_resolvers_and_bearer_parsing() -> None:
    with pytest.raises(ValueError, match="no key resolver"):
        Authenticator(trusted_issuers(), {}, clock=FakeClock())
    assert bearer_token("bearer abc") == "abc"
    with pytest.raises(UnauthorizedError):
        unverified_claims("x.y.z")


async def test_remote_jwks_cache_and_failures(enterprise_idp: FakeIdp) -> None:
    calls = {"n": 0}
    now = {"t": 0.0}

    def handler(_: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 3:
            return httpx.Response(500)
        return httpx.Response(200, json=enterprise_idp.jwks())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        jwks = RemoteJwks("https://idp/jwks", client=client, monotonic=lambda: now["t"])
        await jwks.key_for("k1")
        await jwks.key_for("k1")
        assert calls["n"] == 1
        with pytest.raises(UnauthorizedError, match="unknown signing key"):
            await jwks.key_for("other")  # refresh is rate limited
        now["t"] = 40.0
        with pytest.raises(UnauthorizedError, match="unknown signing key"):
            await jwks.key_for("other")
        assert calls["n"] == 2
        now["t"] = 400.0
        assert await jwks.key_for("k1") is not None  # stale cache tolerated on refresh failure
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(502))
    ) as down:
        with pytest.raises(UnauthorizedError, match="cannot fetch"):
            await RemoteJwks("https://idp/jwks", client=down).key_for("unknown")


# -------------------------------------------------------------- access control


def controller(
    fabric: IdentityFabricClient | None = None,
) -> tuple[AccessController, InMemoryAuditSink]:
    sink = InMemoryAuditSink()
    audit = AuditLog(sink, Ed25519PrivateKey.generate(), key_id="k")
    engine = PolicyEngine(PolicySet.from_file(ROOT / "policies" / "platform-access.yaml"))
    return AccessController(engine, audit, fabric, RedTeamMetrics()), sink


def person(
    *roles: str, sub: str = "alice@corp.test", kind: PrincipalKind = PrincipalKind.USER
) -> Principal:
    return Principal(
        subject=sub, issuer="https://login.corp.test/tenant", kind=kind, roles=frozenset(roles)
    )


async def test_role_based_access() -> None:
    access, sink = controller()
    await access.authorize(person("redteam-auditor"), Action.RUNS_READ)
    await access.authorize(
        person("release-pipeline", kind=PrincipalKind.PIPELINE), Action.RUNS_START
    )
    with pytest.raises(ForbiddenError, match="not permitted"):
        await access.authorize(person("redteam-auditor"), Action.RUNS_START)
    with pytest.raises(ForbiddenError):
        await access.authorize(person(), Action.SUITES_READ)
    assert [e.action for e in sink.events] == ["access.denied", "access.denied"]
    assert sink.events[0].details["requested"] == Action.RUNS_START


async def test_approval_rules() -> None:
    access, _ = controller()
    approver = person("release-approver", sub="bob@corp.test")
    await access.authorize(
        approver, Action.GATE_APPROVE, attributes={"requested_by": "pipeline-subject"}
    )
    with pytest.raises(ForbiddenError, match="explicit deny"):
        await access.authorize(
            approver, Action.GATE_APPROVE, attributes={"requested_by": "bob@corp.test"}
        )
    pipeline = person("release-approver", kind=PrincipalKind.PIPELINE)
    with pytest.raises(ForbiddenError):
        await access.authorize(pipeline, Action.GATE_APPROVE, attributes={"requested_by": "x"})


async def test_agents_need_the_fabric_and_never_approve() -> None:
    access, sink = controller()
    agent = Principal(
        subject="spiffe://a", issuer=FABRIC_ISSUER, kind=PrincipalKind.AGENT, credential="t"
    )
    with pytest.raises(ForbiddenError, match="without an identity fabric"):
        await access.authorize(agent, Action.RUNS_READ)
    with pytest.raises(ForbiddenError, match="must be performed by a person"):
        await access.authorize(agent, Action.GATE_APPROVE)
    assert len(sink.events) == 2


def fabric_client(handler: Any, tmp_path: Path | None = None, **kw: Any) -> IdentityFabricClient:
    return IdentityFabricClient(
        "https://identity.corp.test/",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        clock=FakeClock(),
        **kw,
    )


def decision(value: str) -> dict[str, Any]:
    return {
        "decision": value,
        "agent": "spiffe://a",
        "action": "redteam.runs:start",
        "resource": "target:t1",
        "matched_rules": ["r"],
        "reason": "because",
    }


@pytest.mark.parametrize(
    ("value", "error"),
    [("allow", None), ("deny", ForbiddenError), ("require_approval", ApprovalRequiredError)],
)
async def test_agent_access_follows_fabric_decisions(
    value: str, error: type[Exception] | None
) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=decision(value))

    access, _ = controller(fabric_client(handler))
    agent = Principal(
        subject="spiffe://a", issuer=FABRIC_ISSUER, kind=PrincipalKind.AGENT, credential="tok"
    )
    if error is None:
        await access.authorize(agent, Action.RUNS_START, resource_type="target", resource_id="t1")
    else:
        with pytest.raises(error):
            await access.authorize(agent, Action.RUNS_START)
    assert seen["auth"] == "Bearer tok"
    assert seen["body"]["action"] == Action.RUNS_START


async def test_human_require_approval_policy_outcome() -> None:
    sink = InMemoryAuditSink()
    engine = PolicyEngine(
        PolicySet.model_validate(
            {
                "name": "p",
                "version": "1",
                "rules": [{"id": "hold", "effect": "require_approval", "actions": ["*"]}],
            }
        )
    )
    access = AccessController(
        engine, AuditLog(sink, Ed25519PrivateKey.generate(), key_id="k"), None, RedTeamMetrics()
    )
    with pytest.raises(ApprovalRequiredError):
        await access.authorize(person("redteam-operator"), Action.RUNS_START)


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (httpx.Response(401), UnauthorizedError, "rejected"),
        (httpx.Response(403), ForbiddenError, "refused"),
        (httpx.Response(500), DependencyUnavailableError, "HTTP 500"),
        (httpx.Response(200, json={"nope": 1}), DependencyUnavailableError, "unreadable"),
    ],
)
async def test_fabric_authorize_fails_closed(
    response: httpx.Response, error: type[Exception], message: str
) -> None:
    client = fabric_client(lambda _: response)
    with pytest.raises(error, match=message):
        await client.authorize("t", action="a", resource_type="r")


async def test_fabric_unreachable_and_introspection() -> None:
    def down(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("x")

    with pytest.raises(DependencyUnavailableError, match="unreachable"):
        await fabric_client(down).authorize("t", action="a", resource_type="r")
    ok = fabric_client(lambda _: httpx.Response(200, json={"active": True, "sub": "s"}))
    assert (await ok.introspect("t")).active
    with pytest.raises(DependencyUnavailableError, match="HTTP 503"):
        await fabric_client(lambda _: httpx.Response(503)).introspect("t")
    with pytest.raises(DependencyUnavailableError, match="unreadable"):
        await fabric_client(lambda _: httpx.Response(200, json=[1])).introspect("t")


async def test_fabric_access_token_cached_until_refresh(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("workload-jwt\n", encoding="utf-8")
    calls: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(dict(httpx.QueryParams(request.content.decode())))
        return httpx.Response(200, json={"access_token": f"at-{len(calls)}", "expires_in": 600})

    clock = FakeClock()
    client = IdentityFabricClient(
        "https://identity.corp.test",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        clock=clock,
        client_id="spiffe://corp/agent/platform/red-team",
        workload_token_file=token_file,
        scope="target:invoke",
    )
    assert await client.access_token() == "at-1"
    assert await client.access_token() == "at-1"
    clock.advance(560)
    assert await client.access_token() == "at-2"
    assert calls[0]["assertion"] == "workload-jwt"
    assert calls[0]["scope"] == "target:invoke"


async def test_fabric_access_token_failures(tmp_path: Path) -> None:
    with pytest.raises(DependencyUnavailableError, match="CRT_FABRIC_CLIENT_ID"):
        await fabric_client(lambda _: httpx.Response(200)).access_token()
    missing = fabric_client(
        lambda _: httpx.Response(200), client_id="c", workload_token_file=tmp_path / "absent"
    )
    with pytest.raises(DependencyUnavailableError, match="unreadable"):
        await missing.access_token()
    token_file = tmp_path / "t"
    token_file.write_text("jwt", encoding="utf-8")
    refused = fabric_client(
        lambda _: httpx.Response(400), client_id="c", workload_token_file=token_file
    )
    with pytest.raises(DependencyUnavailableError, match="HTTP 400"):
        await refused.access_token()
    empty = fabric_client(
        lambda _: httpx.Response(200, json={"token_type": "Bearer"}),
        client_id="c",
        workload_token_file=token_file,
    )
    with pytest.raises(DependencyUnavailableError, match="no access token"):
        await empty.access_token()


def test_static_jwks_ignores_keys_without_kid(enterprise_idp: FakeIdp) -> None:
    document = enterprise_idp.jwks()
    document["keys"].append({k: v for k, v in document["keys"][0].items() if k != "kid"})
    assert StaticJwks(document)._keys.keys() == {"k1"}
    assert AUDIENCE == "continuous-red-teaming"
