"""Typed client for agent-identity-fabric.

* ``authorize``: inbound agent requests are authorized by the fabric's
  ``/v1/authorize`` policy decision point, which also validates the agent's
  credential (signature, epoch, revocation, delegation chain).
* ``introspect``: RFC 7662 token status.
* ``access_token``: the platform's own credential (RFC 7523 jwt-bearer grant
  with its projected workload token) for calling targets that require one.

Every failure fails closed: no decision means no access.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
from agentic_core.domain.classification import Decision
from pydantic import BaseModel, ConfigDict, ValidationError

from continuous_red_teaming.domain.errors import (
    DependencyUnavailableError,
    ForbiddenError,
    UnauthorizedError,
)
from continuous_red_teaming.domain.ports import Clock

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class FabricDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    decision: Decision
    agent: str
    action: str
    resource: str
    matched_rules: tuple[str, ...] = ()
    policy_version: str = ""
    reason: str = ""


class FabricIntrospection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    active: bool
    sub: str | None = None
    scope: str | None = None
    exp: int | None = None


class IdentityFabricClient:
    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.AsyncClient,
        clock: Clock,
        client_id: str | None = None,
        workload_token_file: Path | None = None,
        scope: str | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._client = client
        self._clock = clock
        self._client_id = client_id
        self._workload_token_file = workload_token_file
        self._scope = scope
        self._cached: tuple[str, float] | None = None
        self._lock = asyncio.Lock()

    async def _post(
        self, path: str, *, headers: dict[str, str] | None = None, **kwargs: Any
    ) -> httpx.Response:
        try:
            return await self._client.post(f"{self._base}{path}", headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise DependencyUnavailableError("identity fabric unreachable") from exc

    async def authorize(
        self,
        token: str,
        *,
        action: str,
        resource_type: str,
        resource_id: str = "*",
        attributes: dict[str, Any] | None = None,
    ) -> FabricDecision:
        response = await self._post(
            "/v1/authorize",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "resource_attributes": attributes or {},
            },
        )
        if response.status_code == 401:
            raise UnauthorizedError("agent credential rejected by identity fabric")
        if response.status_code == 403:
            raise ForbiddenError("identity fabric refused the request")
        if response.status_code != 200:
            raise DependencyUnavailableError(
                f"identity fabric returned HTTP {response.status_code}"
            )
        try:
            return FabricDecision.model_validate(response.json())
        except (ValidationError, ValueError) as exc:
            raise DependencyUnavailableError("identity fabric decision unreadable") from exc

    async def introspect(self, token: str) -> FabricIntrospection:
        response = await self._post("/oauth2/introspect", data={"token": token})
        if response.status_code != 200:
            raise DependencyUnavailableError(
                f"identity fabric introspection returned HTTP {response.status_code}"
            )
        try:
            return FabricIntrospection.model_validate(response.json())
        except (ValidationError, ValueError) as exc:
            raise DependencyUnavailableError("introspection response unreadable") from exc

    async def access_token(self) -> str:
        """Platform credential for outbound calls, cached until shortly before expiry."""
        if self._client_id is None or self._workload_token_file is None:
            raise DependencyUnavailableError(
                "outbound fabric credentials need CRT_FABRIC_CLIENT_ID and "
                "CRT_FABRIC_WORKLOAD_TOKEN_FILE"
            )
        async with self._lock:
            now = self._clock.now().timestamp()
            if self._cached is not None and now < self._cached[1]:
                return self._cached[0]
            try:
                # Projected service-account tokens rotate on disk; read every time.
                assertion = await asyncio.to_thread(
                    self._workload_token_file.read_text, encoding="utf-8"
                )
            except OSError as exc:
                raise DependencyUnavailableError("workload token file unreadable") from exc
            data = {
                "grant_type": JWT_BEARER,
                "client_id": self._client_id,
                "assertion": assertion.strip(),
            }
            if self._scope:
                data["scope"] = self._scope
            response = await self._post("/oauth2/token", data=data)
            if response.status_code != 200:
                raise DependencyUnavailableError(
                    f"identity fabric token endpoint returned HTTP {response.status_code}"
                )
            body = response.json()
            token = body.get("access_token") if isinstance(body, dict) else None
            if not isinstance(token, str) or not token:
                raise DependencyUnavailableError("identity fabric issued no access token")
            lifetime = int(body.get("expires_in", 300))
            refresh_at = self._clock.now() + timedelta(seconds=max(0, lifetime - 60))
            self._cached = (token, refresh_at.timestamp())
            return token
