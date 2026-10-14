"""Gate client pieces that do not need the API: OIDC token retrieval, transport, errors."""

from __future__ import annotations

import io
import json
import urllib.error
from typing import Any

import pytest

from continuous_red_teaming import gate_client


def fake_transport(status: int, body: Any) -> gate_client.Transport:
    def transport(
        method: str, url: str, headers: dict[str, str], payload: bytes | None
    ) -> tuple[int, bytes]:
        transport.seen = (method, url, headers)  # type: ignore[attr-defined]
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return status, raw

    return transport


def test_github_oidc_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.test/id?api=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-token")
    transport = fake_transport(200, {"value": "oidc-jwt"})
    assert gate_client.github_oidc_token("crt api", transport) == "oidc-jwt"
    _, url, headers = transport.seen  # type: ignore[attr-defined]
    assert url == "https://token.actions.test/id?api=1&audience=crt%20api"
    assert headers["Authorization"] == "Bearer runner-token"
    with pytest.raises(gate_client.GateClientError, match="HTTP 403"):
        gate_client.github_oidc_token("a", fake_transport(403, {}))
    with pytest.raises(gate_client.GateClientError, match="no token"):
        gate_client.github_oidc_token("a", fake_transport(200, {"value": ""}))


def test_github_oidc_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    monkeypatch.delenv("CRT_GATE_TOKEN", raising=False)
    with pytest.raises(gate_client.GateClientError, match="id-token: write"):
        gate_client.github_oidc_token("a")
    argv = ["--url", "https://x", "--target-id", "t", "--target-version", "1", "--suite", "s"]
    assert gate_client.main(argv) == 2


def test_api_error_handling() -> None:
    api = gate_client.GateApi(
        "https://x/", "tok", fake_transport(404, {"error_description": "gone"})
    )
    with pytest.raises(gate_client.GateClientError, match="HTTP 404: gone"):
        api.call("GET", "/v1/runs/r")
    garbled = gate_client.GateApi("https://x", "tok", fake_transport(200, b"<html>"))
    with pytest.raises(gate_client.GateClientError, match="not JSON"):
        garbled.call("GET", "/v1/runs/r")
    listed = gate_client.GateApi("https://x", "tok", fake_transport(500, [1]))
    with pytest.raises(gate_client.GateClientError, match="HTTP 500"):
        listed.call("POST", "/v1/runs", {"a": 1})


def test_run_that_does_not_finish_or_fails() -> None:
    states = iter(["queued", "running", "running"])

    def transport(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        if method == "POST":
            return 202, json.dumps({"id": "r1", "probe_count": 1, "seed": 1}).encode()
        return 200, json.dumps({"id": "r1", "status": next(states, "running")}).encode()

    clock = iter(range(0, 10_000, 100))
    options = gate_client.Options(
        url="https://x",
        target_id="t",
        target_version="1",
        suite="s",
        timeout_s=150,
        sleep=lambda _: None,
        clock=lambda: float(next(clock)),
        log=lambda _: None,
    )
    with pytest.raises(gate_client.GateClientError, match="did not finish"):
        gate_client.run_gate(gate_client.GateApi("https://x", "t", transport), options)

    def failed(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        if method == "POST":
            return 202, json.dumps({"id": "r2", "probe_count": 1, "seed": 1}).encode()
        return 200, json.dumps({"id": "r2", "status": "failed", "error": "suite changed"}).encode()

    with pytest.raises(gate_client.GateClientError, match="suite changed"):
        gate_client.run_gate(gate_client.GateApi("https://x", "t", failed), options)


def test_invalid_signature_is_an_operational_error() -> None:
    def transport(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        if url.endswith("/v1/runs"):
            return 202, json.dumps({"id": "r", "probe_count": 1, "seed": 1}).encode()
        if url.endswith("/gate"):
            return 201, json.dumps({"id": "d", "outcome": "pass", "signed_report": {}}).encode()
        if url.endswith("/verify"):
            return 200, json.dumps({"valid": False, "reason": "tampered"}).encode()
        return 200, json.dumps({"id": "r", "status": "completed", "seed": 1}).encode()

    options = gate_client.Options(
        url="https://x", target_id="t", target_version="1", suite="s", log=lambda _: None
    )
    with pytest.raises(gate_client.GateClientError, match="tampered"):
        gate_client.run_gate(gate_client.GateApi("https://x", "t", transport), options)


def test_urllib_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response(io.BytesIO):
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_: object) -> None:
            self.close()

    monkeypatch.setattr(gate_client.urllib.request, "urlopen", lambda *a, **k: Response(b"{}"))
    assert gate_client.urllib_transport("GET", "https://x", {}, None) == (200, b"{}")

    def http_error(*_: Any, **__: Any) -> Any:
        raise urllib.error.HTTPError("https://x", 409, "conflict", {}, io.BytesIO(b'{"e":1}'))  # type: ignore[arg-type]

    monkeypatch.setattr(gate_client.urllib.request, "urlopen", http_error)
    assert gate_client.urllib_transport("POST", "https://x", {}, b"{}") == (409, b'{"e":1}')

    def unreachable(*_: Any, **__: Any) -> Any:
        raise urllib.error.URLError("dns failure")

    monkeypatch.setattr(gate_client.urllib.request, "urlopen", unreachable)
    with pytest.raises(gate_client.GateClientError, match="cannot reach"):
        gate_client.urllib_transport("GET", "https://x", {}, None)
    with pytest.raises(gate_client.GateClientError, match="unsupported URL"):
        gate_client.urllib_transport("GET", "ftp://x", {}, None)
