"""Inbound authentication.

Three kinds of callers reach the platform:

* people (red-team operators, release approvers, auditors) with tokens from
  the enterprise OIDC provider;
* CI pipelines with workload OIDC tokens (for example GitHub Actions
  ``token.actions.githubusercontent.com``), restricted by subject pattern;
* AI agents with credentials from the agent identity fabric. Those tokens are
  not verified here: the fabric verifies them in ``/v1/authorize`` together
  with the authorization decision, so an agent is never trusted on the basis
  of an unverified claim.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping, Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from continuous_red_teaming.domain.errors import UnauthorizedError
from continuous_red_teaming.domain.ports import Clock
from continuous_red_teaming.security.jwks import KeyResolver, unverified_claims, verify_jwt


class PrincipalKind(StrEnum):
    USER = "user"
    PIPELINE = "pipeline"
    AGENT = "agent"


class TrustedIssuer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    issuer: str = Field(min_length=8)
    jwks_url: str = Field(min_length=8)
    audience: str = Field(min_length=1)
    kind: PrincipalKind = PrincipalKind.USER
    roles_claim: str = "roles"
    default_roles: tuple[str, ...] = ()
    subject_patterns: tuple[str, ...] = ("*",)


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    issuer: str
    kind: PrincipalKind
    roles: frozenset[str] = frozenset()
    credential: str = Field(default="", repr=False, exclude=True)

    @property
    def is_agent(self) -> bool:
        return self.kind is PrincipalKind.AGENT


def bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UnauthorizedError("bearer token required")
    token = authorization[7:].strip()
    if not token:
        raise UnauthorizedError("bearer token required")
    return token


class Authenticator:
    def __init__(
        self,
        issuers: Sequence[TrustedIssuer],
        resolvers: Mapping[str, KeyResolver],
        *,
        clock: Clock,
        fabric_issuer: str | None = None,
    ) -> None:
        self._issuers = {i.issuer: i for i in issuers}
        missing = set(self._issuers) - set(resolvers)
        if missing:
            raise ValueError(f"no key resolver for issuers {sorted(missing)}")
        self._resolvers = dict(resolvers)
        self._clock = clock
        self._fabric_issuer = fabric_issuer

    async def authenticate(self, authorization: str | None) -> Principal:
        token = bearer_token(authorization)
        issuer = str(unverified_claims(token).get("iss", ""))
        trusted = self._issuers.get(issuer)
        if trusted is not None:
            return await self._verify(token, trusted)
        if self._fabric_issuer is not None and issuer == self._fabric_issuer:
            subject = str(unverified_claims(token).get("sub", ""))
            if not subject:
                raise UnauthorizedError("agent credential has no subject")
            return Principal(
                subject=subject, issuer=issuer, kind=PrincipalKind.AGENT, credential=token
            )
        raise UnauthorizedError("token issuer is not trusted")

    async def _verify(self, token: str, trusted: TrustedIssuer) -> Principal:
        claims = await verify_jwt(
            token,
            self._resolvers[trusted.issuer],
            issuer=trusted.issuer,
            audience=trusted.audience,
            now=self._clock.now(),
        )
        subject = str(claims["sub"])
        if not any(fnmatch.fnmatchcase(subject, p) for p in trusted.subject_patterns):
            raise UnauthorizedError("token subject is not permitted for this issuer")
        raw = claims.get(trusted.roles_claim, [])
        roles = {r for r in raw if isinstance(r, str)} if isinstance(raw, list) else set()
        return Principal(
            subject=subject,
            issuer=trusted.issuer,
            kind=trusted.kind,
            roles=frozenset(roles | set(trusted.default_roles)),
            credential=token,
        )
