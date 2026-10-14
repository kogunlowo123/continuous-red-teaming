"""The platform validating a networked agent over HTTP, A2A and MCP gives identical results."""

from __future__ import annotations

from pathlib import Path

import httpx
import httpx2
import pytest
import yaml
from agentic_core.policy import PolicyEngine, PolicySet

from continuous_red_teaming.adapters.reference import ReferenceAgent
from continuous_red_teaming.adapters.reference_server import create_reference_app
from continuous_red_teaming.application.service import RunRequest
from continuous_red_teaming.domain.models import (
    ProbeOutcome,
    ReferenceProfile,
    RunStatus,
    TargetKind,
    TargetRegistration,
)
from continuous_red_teaming.runtime.container import build_container
from tests.conftest import ROOT, FakeIdp, make_settings, resolvers

pytestmark = pytest.mark.e2e

PROFILE = ReferenceProfile(
    marker_leak_rate=0.3, secret_echo_rate=0.3, forbidden_tool_rate=0.3, approval_bypass_rate=0.3
)


def compact_suite(directory: Path) -> None:
    """Every scenario of the shipped suite, sampled down to six cases each."""
    document = yaml.safe_load((ROOT / "suites" / "agent-baseline.yaml").read_text("utf-8"))
    document["name"] = "agent-baseline-sample"
    for scenario in document["scenarios"]:
        scenario["samples"] = 6
        scenario.pop("repeats", None)
    directory.mkdir()
    (directory / "sample.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")


async def test_same_verdicts_over_every_protocol(
    tmp_path: Path, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    compact_suite(tmp_path / "suites")
    policy = PolicyEngine(PolicySet.from_file(ROOT / "policies" / "target-tool-policy.yaml"))
    agent_app = create_reference_app(
        ReferenceAgent(PROFILE, policy), allowed_hosts=["agents.corp.test"]
    )
    settings = make_settings(
        tmp_path,
        suites_dir=tmp_path / "suites",
        target_allowed_hosts=["agents.corp.test"],
    )
    async with agent_app.router.lifespan_context(agent_app):
        built = await build_container(
            settings,
            issuer_resolvers=resolvers(enterprise_idp, ci_idp),
            http=httpx.AsyncClient(transport=httpx.ASGITransport(app=agent_app)),
            env={"AGENT_TOKEN": "token-for-tests"},
            mcp_transport_factory=lambda: httpx2.ASGITransport(app=agent_app),
        )
        try:
            service = built.service
            outcomes: dict[str, list[ProbeOutcome]] = {}
            registrations = {
                "reference": TargetRegistration(
                    name="in-process",
                    kind=TargetKind.REFERENCE,
                    reference_profile=PROFILE,
                    owner="team",
                ),
                "http": TargetRegistration(
                    name="over-http",
                    kind=TargetKind.HTTP,
                    owner="team",
                    endpoint="https://agents.corp.test/invoke",
                    trace_endpoint="https://agents.corp.test/trace",
                    auth="env_bearer",
                    auth_env="AGENT_TOKEN",
                ),
                "a2a": TargetRegistration(
                    name="over-a2a",
                    kind=TargetKind.A2A,
                    owner="team",
                    endpoint="https://agents.corp.test/a2a",
                ),
                "mcp": TargetRegistration(
                    name="over-mcp",
                    kind=TargetKind.MCP,
                    owner="team",
                    endpoint="https://agents.corp.test/mcp/",
                ),
            }
            for label, registration in registrations.items():
                target = await service.register_target(registration, actor="alice")
                run = await service.create_run(
                    RunRequest(
                        target_id=target.id,
                        target_version="1.0.0",
                        suite="agent-baseline-sample",
                        seed=21,
                    ),
                    actor="pipeline",
                )
                finished = await service.execute_run(run.id)
                assert finished.status is RunStatus.COMPLETED, finished.error
                results = await service.run_results(run.id, limit=1000)
                outcomes[label] = [r.outcome for r in results]
                if label == "http":
                    assert all(
                        r.evidence is not None and r.evidence.trace_source == "external"
                        for r in results
                    )
            assert ProbeOutcome.FAIL in outcomes["reference"]
            assert ProbeOutcome.ERROR not in outcomes["reference"]
            assert outcomes["http"] == outcomes["reference"]
            assert outcomes["a2a"] == outcomes["reference"]
            assert outcomes["mcp"] == outcomes["reference"]
        finally:
            await built.aclose()
