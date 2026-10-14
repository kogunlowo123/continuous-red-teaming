"""A2A (agent card, message/send, tasks/get) and MCP tools, exercised as agents call them."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from continuous_red_teaming.api.app import create_app
from continuous_red_teaming.config import Settings
from continuous_red_teaming.runtime.container import Container, build_container
from tests.conftest import (
    FakeClock,
    FakeIdp,
    pipeline_headers,
    reference_registration,
    resolvers,
    user_headers,
)

pytestmark = pytest.mark.e2e


def rpc(client: TestClient, headers: dict[str, str], method: str, params: Any) -> dict[str, Any]:
    response = client.post(
        "/a2a",
        json={"jsonrpc": "2.0", "id": "1", "method": method, "params": params},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def skill(name: str, **arguments: Any) -> dict[str, Any]:
    return {
        "message": {
            "kind": "message",
            "role": "user",
            "messageId": "m-1",
            "parts": [{"kind": "data", "data": {"skill": name, **arguments}}],
        }
    }


def test_agent_card(client: TestClient) -> None:
    card = client.get("/.well-known/agent-card.json").json()
    for field in ("name", "description", "url", "version", "capabilities", "skills"):
        assert field in card
    assert card["url"] == "https://redteam.corp.test/a2a"
    assert card["securitySchemes"]["bearer"]["scheme"] == "bearer"
    assert {s["id"] for s in card["skills"]} == {
        "start-validation-run",
        "evaluate-release-gate",
        "compare-versions",
    }


def test_a2a_validation_and_gate(
    client: TestClient, enterprise_idp: FakeIdp, ci_idp: FakeIdp
) -> None:
    operator = user_headers(enterprise_idp, "redteam-operator")
    target = client.post(
        "/v1/targets",
        json=reference_registration().model_dump(mode="json"),
        headers=operator,
    ).json()
    pipeline = pipeline_headers(ci_idp)
    started = rpc(
        client,
        pipeline,
        "message/send",
        skill(
            "start-validation-run",
            target_id=target["id"],
            target_version="2.0.0",
            suite="agent-baseline",
            seed=3,
        ),
    )["result"]
    assert started["kind"] == "task"
    assert started["status"]["state"] == "submitted"
    deadline = time.monotonic() + 60
    state = started
    while state["status"]["state"] not in {"completed", "failed", "canceled"}:
        assert time.monotonic() < deadline
        time.sleep(0.05)
        state = rpc(client, pipeline, "tasks/get", {"id": started["id"]})["result"]
    assert state["status"]["state"] == "completed"

    gated = rpc(
        client, pipeline, "message/send", skill("evaluate-release-gate", run_id=started["id"])
    )
    data = gated["result"]["artifacts"][0]["parts"][0]["data"]
    assert gated["result"]["status"]["state"] == "completed"
    assert data["outcome"] == "pass"
    assert data["releasable"] is True
    by_id = rpc(client, pipeline, "tasks/get", {"id": data["decision_id"]})["result"]
    assert by_id["artifacts"][0]["parts"][0]["data"]["outcome"] == "pass"

    compared = rpc(
        client,
        pipeline,
        "message/send",
        skill("compare-versions", target_id=target["id"], baseline="2.0.0", candidate="2.0.0"),
    )
    assert compared["result"]["status"]["state"] == "completed"


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({"jsonrpc": "1.0", "id": 1, "method": "message/send", "params": {}}, -32600),
        ({"jsonrpc": "2.0", "id": 1, "method": "tasks/cancel", "params": {}}, -32601),
        ({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": []}, -32602),
        ({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {}}, -32602),
        ({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": skill("unknown")}, -32602),
        (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": skill("evaluate-release-gate"),
            },
            -32602,
        ),
        ({"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {}}, -32602),
        ({"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {"id": "nope"}}, -32001),
        (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": skill("evaluate-release-gate", run_id="missing"),
            },
            -32001,
        ),
    ],
)
def test_a2a_protocol_errors(client: TestClient, ci_idp: FakeIdp, payload: Any, code: int) -> None:
    response = client.post("/a2a", json=payload, headers=pipeline_headers(ci_idp))
    assert response.json()["error"]["code"] == code


def test_a2a_authentication_and_authorization(client: TestClient, enterprise_idp: FakeIdp) -> None:
    assert client.post("/a2a", json={}).status_code == 401
    auditor = user_headers(enterprise_idp, "redteam-auditor")
    forbidden = rpc(
        client,
        auditor,
        "message/send",
        skill("start-validation-run", target_id="t", target_version="1", suite="agent-baseline"),
    )
    assert forbidden["error"]["code"] == -32003
    unparseable = client.post("/a2a", content=b"{", headers=auditor)
    assert unparseable.json()["error"]["code"] == -32700


# -------------------------------------------------------------------------- MCP


@asynccontextmanager
async def running_platform(
    settings: Settings, enterprise: FakeIdp, ci: FakeIdp, clock: FakeClock
) -> AsyncIterator[FastAPI]:
    async def factory() -> Container:
        return await build_container(
            settings, issuer_resolvers=resolvers(enterprise, ci), clock=clock
        )

    app = create_app(factory, mcp_allowed_hosts=["redteam.corp.test"])
    async with app.router.lifespan_context(app):
        yield app


@asynccontextmanager
async def mcp_session(app: FastAPI, headers: dict[str, str]) -> AsyncIterator[Client]:
    async with (
        httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=headers) as http,
        Client(
            streamable_http_client("https://redteam.corp.test/mcp/", http_client=http), cache=None
        ) as session,
    ):
        yield session


async def test_mcp_tools_end_to_end(
    settings: Settings, enterprise_idp: FakeIdp, ci_idp: FakeIdp, clock: FakeClock
) -> None:
    async with running_platform(settings, enterprise_idp, ci_idp, clock) as app:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://redteam.corp.test"
        ) as rest:
            created = await rest.post(
                "/v1/targets",
                json=reference_registration().model_dump(mode="json"),
                headers=user_headers(enterprise_idp, "redteam-operator"),
            )
            target_id = created.json()["id"]

        async with mcp_session(app, pipeline_headers(ci_idp)) as session:
            tools = {t.name: t for t in (await session.list_tools()).tools}
            assert set(tools) == {
                "list_suites",
                "start_validation_run",
                "get_run",
                "evaluate_release_gate",
                "compare_versions",
            }
            assert all(t.output_schema for t in tools.values())
            suites = await session.call_tool("list_suites", {})
            assert suites.structured_content["suites"][0]["name"] == "agent-baseline"
            started = await session.call_tool(
                "start_validation_run",
                {"target_id": target_id, "target_version": "4.0.0", "suite": "agent-baseline"},
            )
            assert not started.is_error, started.content
            run_id = started.structured_content["run_id"]
            for _ in range(600):
                status = await session.call_tool("get_run", {"run_id": run_id})
                if status.structured_content["status"] == "completed":
                    break
                await asyncio.sleep(0.05)
            assert status.structured_content["failures"] == 0
            decision = await session.call_tool("evaluate_release_gate", {"run_id": run_id})
            assert decision.structured_content["outcome"] == "pass"
            assert decision.structured_content["report_digest"].startswith("sha256:")
            missing = await session.call_tool(
                "compare_versions", {"target_id": target_id, "baseline": "1", "candidate": "4.0.0"}
            )
            assert missing.is_error

        async with mcp_session(app, {}) as anonymous:
            refused = await anonymous.call_tool("list_suites", {})
            assert refused.is_error
        async with mcp_session(app, user_headers(enterprise_idp, "redteam-auditor")) as auditor:
            denied = await auditor.call_tool(
                "start_validation_run",
                {"target_id": target_id, "target_version": "5", "suite": "agent-baseline"},
            )
            assert denied.is_error

        container: Container = app.state.container
        actions = [e.action async for e in container.audit._sink.read()]
        assert "mcp.start_validation_run" in actions
        assert "mcp.evaluate_release_gate" in actions
