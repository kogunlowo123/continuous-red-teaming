"""Signed evaluation reports.

The report is serialized as canonical JSON (sorted keys, no whitespace), its
SHA-256 digest is signed with the platform's Ed25519 audit key (the same
signer agentic-core's AuditLog uses), and the gate decision is recorded in
the hash-chained audit log with that digest. Anyone holding the public key
(published at ``/.well-known/report-signing-keys``) can verify a report
offline; the audit chain proves when it was issued and by which policy.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from typing import Any

from agentic_core.domain.provenance import canonical_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict

from continuous_red_teaming.domain.models import EvaluationReport, ReportSignature, SignedReport


def report_digest(report: EvaluationReport) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(report.model_dump(mode="json"))).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_jwk(key: Ed25519PublicKey, kid: str) -> dict[str, str]:
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }


class Verification(BaseModel):
    model_config = ConfigDict(frozen=True)

    valid: bool
    key_id: str
    digest: str
    reason: str


class ReportSigner:
    def __init__(
        self,
        key: Ed25519PrivateKey,
        key_id: str,
        *,
        retired: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> None:
        self._key = key
        self._key_id = key_id
        self._public: dict[str, Ed25519PublicKey] = {**(retired or {}), key_id: key.public_key()}

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, report: EvaluationReport) -> SignedReport:
        digest = report_digest(report)
        value = self._key.sign(bytes.fromhex(digest.removeprefix("sha256:")))
        return SignedReport(
            report=report,
            signature=ReportSignature(
                key_id=self._key_id, digest=digest, value=base64.b64encode(value).decode()
            ),
        )

    def verify(self, signed: SignedReport) -> Verification:
        signature = signed.signature
        digest = report_digest(signed.report)

        def result(valid: bool, reason: str) -> Verification:
            return Verification(valid=valid, key_id=signature.key_id, digest=digest, reason=reason)

        if signature.alg != "EdDSA":
            return result(False, f"unsupported algorithm {signature.alg}")
        if digest != signature.digest:
            return result(False, "report content does not match the signed digest")
        key = self._public.get(signature.key_id)
        if key is None:
            return result(False, f"unknown key id {signature.key_id!r}")
        try:
            key.verify(base64.b64decode(signature.value, validate=True), bytes.fromhex(digest[7:]))
        except (InvalidSignature, ValueError):
            return result(False, "signature does not verify")
        return result(True, "signature valid")

    def jwks(self) -> dict[str, Any]:
        return {"keys": [public_jwk(key, kid) for kid, key in sorted(self._public.items())]}
