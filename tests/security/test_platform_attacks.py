"""Adversarial tests mapped to the threat model (docs/security/threat-model.md)."""

from __future__ import annotations

import base64
import json
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from continuous_red_teaming.domain.errors import TargetPolicyError
from continuous_red_teaming.domain.models import ReferenceProfile
from continuous_red_teaming.judges.markers import disclosure_forms
from continuous_red_teaming.security.egress import EgressPolicy
from tests.conftest import (
    AUDIENCE,
    CI_ISSUER,
    ENTERPRISE_ISSUER,
    FakeIdp,
    pipeline_headers,
    reference_registration,
    user_headers,
)

pytestmark = pytest.mark.security

PROTECTED = [
    ("GET", "/v1/suites"),
    ("GET", "/v1/targets"),
    ("POST", "/v1/targets"),
    ("GET", "/v1/runs"),
    ("POST", "/v1/runs"),
    ("GET", "/v1/gate/decisions"),
    ("POST", "/v1/reports/verify"),
    ("GET", "/v1/judges/llm"),
]


def _b64(obj: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_s1_every_api_route_requires_authentication(
    client: TestClient, method: str, path: str
) -> None:
    response = client.request(method, path, json={})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["error"] == "unauthorized"


def test_s2_forged_and_unsigned_tokens(client: TestClient, enterprise_idp: FakeIdp) -> None:
    claims = jwt.decode(
        enterprise_idp.mint(sub="mallory", roles=["redteam-operator"]),
        options={"verify_signature": False},
    )
    forged = jwt.encode(
        claims, ec.generate_private_key(ec.SECP256R1()), algorithm="ES256", headers={"kid": "k1"}
    )
    unsigned = f"{_b64({'alg': 'none', 'kid': 'k1'})}.{_b64(claims)}."
    hs256 = jwt.encode(
        claims,
        "guessable-shared-secret-value-of-32-bytes",
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    for token in (forged, unsigned, hs256):
        response = client.get("/v1/targets", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401, token


def test_s3_token_for_another_service_is_rejected(
    client: TestClient, enterprise_idp: FakeIdp
) -> None:
    other = enterprise_idp.mint(sub="alice", aud="some-other-api", roles=["redteam-operator"])
    assert (
        client.get("/v1/targets", headers={"Authorization": f"Bearer {other}"}).status_code == 401
    )


def test_s4_pipeline_from_unapproved_repository(client: TestClient, ci_idp: FakeIdp) -> None:
    fork = pipeline_headers(ci_idp, sub="repo:attacker/fork:ref:refs/heads/main")
    assert client.get("/v1/suites", headers=fork).status_code == 401


def test_s5_role_escalation_is_denied_and_audited(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    auditor = user_headers(enterprise_idp, "redteam-auditor", sub="eve@corp.test")
    registration = reference_registration().model_dump(mode="json")
    assert client.post("/v1/targets", json=registration, headers=auditor).status_code == 403
    pipeline = pipeline_headers(ci_idp)
    assert client.post("/v1/targets", json=registration, headers=pipeline).status_code == 403
    container = client.app.state.container  # type: ignore[attr-defined]
    events = list(container.audit._sink._path.read_text("utf-8").splitlines())
    denied = [json.loads(e) for e in events if '"access.denied"' in e]
    assert {d["actor"] for d in denied} == {"eve@corp.test", pipeline_headers.__defaults__[0]}
    assert "crt_access_denied_total" in client.get("/metrics").text


def test_s6_pipelines_and_requesters_cannot_approve(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    from tests.e2e.test_http_lifecycle import register, run_to_completion

    target_id = register(client, enterprise_idp, "critical-agent", None, risk="critical")  # type: ignore[arg-type]
    requester = user_headers(
        enterprise_idp, "redteam-operator", "release-approver", sub="ivan@corp.test"
    )
    run = run_to_completion(client, requester, target_id, "1.0.0", environment="production")
    decision = client.post(f"/v1/runs/{run['id']}/gate", headers=requester).json()
    assert decision["outcome"] == "require_approval"
    self_approval = client.post(
        f"/v1/gate/decisions/{decision['id']}/approve", json={"reason": "my own"}, headers=requester
    )
    assert self_approval.status_code == 403
    pipeline = client.post(
        f"/v1/gate/decisions/{decision['id']}/approve",
        json={"reason": "automation"},
        headers=pipeline_headers(ci_idp),
    )
    assert pipeline.status_code == 403


def test_s7_agent_credentials_without_fabric_are_refused(client: TestClient) -> None:
    fabric_like = FakeIdp("https://identity.corp.test").mint(sub="spiffe://corp/agent/x/y")
    response = client.get("/v1/suites", headers={"Authorization": f"Bearer {fabric_like}"})
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("endpoint", "reason"),
    [
        ("http://agents.corp.test/invoke", "scheme"),
        ("https://169.254.169.254/latest/meta-data", "refused range"),
        ("https://[fe80::1]/x", "refused range"),
        ("https://0.0.0.0/x", "refused range"),
        ("https://user:pw@agents.corp.test/x", "credentials"),
        ("https://internal-admin.corp.test/x", "allow list"),
        ("https://agents.corp.test.evil.test/x", "allow list"),
        ("file:///etc/passwd", "scheme"),
    ],
)
def test_s8_target_registration_cannot_pivot(
    client: TestClient, enterprise_idp: FakeIdp, endpoint: str, reason: str
) -> None:
    body = {"name": "pivot", "kind": "http", "endpoint": endpoint, "owner": "team"}
    response = client.post(
        "/v1/targets", json=body, headers=user_headers(enterprise_idp, "redteam-operator")
    )
    assert response.status_code == 422
    assert reason in response.json()["error_description"]


def test_s8b_egress_policy_unit() -> None:
    policy = EgressPolicy(["agents.corp.test", "10.0.0.5"], allow_insecure=True)
    assert policy.check("http://agents.corp.test/x")
    assert policy.check("https://10.0.0.5:8443/x")
    with pytest.raises(TargetPolicyError, match="no host"):
        policy.check("https:///nohost")


def test_s9_suites_cannot_smuggle_template_code() -> None:
    from continuous_red_teaming.domain.errors import SuiteValidationError
    from continuous_red_teaming.domain.suites import Suite

    document = {
        "name": "evil",
        "version": "1",
        "scenarios": [
            {
                "id": "x",
                "title": "attribute access attempt",
                "category": "marker_leakage",
                "severity": "low",
                "labels": {"owasp_llm": ["LLM02:2025"]},
                "probe": {
                    "kind": "canary_in_context",
                    "task": "{canary.__class__.__init__.__globals__}",
                    "context": [{"source": "s", "content": "{canary}"}],
                },
            }
        ],
    }
    with pytest.raises(SuiteValidationError, match="placeholders"):
        Suite.from_yaml(json.dumps(document))


def test_s10_marker_evasion_is_detected() -> None:
    marker = "CANARY-6a1f0c3e-2b4d-4e8f-9a7b-5c3d1e0f2a4b"
    evasions = [
        marker.lower(),
        " ".join(marker),
        marker.replace("-", "_"),
        marker[::-1],
        base64.b64encode(marker.encode()).decode(),
        base64.b64encode(("x" + marker).encode()).decode(),
        marker.encode().hex(),
        marker.partition("-")[2],
    ]
    for text in evasions:
        assert disclosure_forms(marker, f"Summary text {text} end"), text


def test_s11_report_forgery_is_detected(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    from tests.e2e.test_http_lifecycle import register, run_to_completion

    pipeline = pipeline_headers(ci_idp)
    target_id = register(client, enterprise_idp, "weak", ReferenceProfile(marker_leak_rate=0.5))
    run = run_to_completion(client, pipeline, target_id, "1.0.0")
    decision = client.post(f"/v1/runs/{run['id']}/gate", headers=pipeline).json()
    assert decision["outcome"] == "fail"
    forged = decision["signed_report"]
    forged["report"]["outcome"] = "pass"
    forged["report"]["matched_rules"] = ["allow-clean-release"]
    verdict = client.post("/v1/reports/verify", json=forged, headers=pipeline).json()
    assert verdict["valid"] is False
    forged["signature"]["digest"] = "sha256:" + "0" * 64
    assert client.post("/v1/reports/verify", json=forged, headers=pipeline).json()["valid"] is False


def test_s12_probes_never_reveal_what_is_tested(client: TestClient, ci_idp: FakeIdp) -> None:
    preview = client.get(
        "/v1/suites/agent-baseline/expansion",
        params={"limit": 50},
        headers=pipeline_headers(ci_idp),
    ).json()
    for probe in preview["probes"]:
        sent = json.dumps(probe["invocation"])
        assert probe["category"] not in sent
        assert probe["kind"] not in sent
        for marker in probe["markers"]:
            assert marker not in probe["invocation"]["task"]


def test_s13_unknown_fields_are_rejected(client: TestClient, enterprise_idp: FakeIdp) -> None:
    body = reference_registration().model_dump(mode="json") | {"is_admin": True}
    response = client.post(
        "/v1/targets", json=body, headers=user_headers(enterprise_idp, "redteam-operator")
    )
    assert response.status_code == 422
    assert response.json()["error"] == "invalid_request"


def test_s14_issuer_constants_are_distinct() -> None:
    assert len({ENTERPRISE_ISSUER, CI_ISSUER}) == 2
    assert AUDIENCE
