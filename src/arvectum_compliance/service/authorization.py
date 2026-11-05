"""Signed per-job authorization; never trust tenant/host labels from a browser."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import asdict, dataclass

from .domain_proof import OwnershipRegistry, ProofError, VerifiedProof, _identifier


@dataclass(frozen=True, slots=True)
class ScanGrant:
    tenant_id: str
    job_id: str
    proof_id: str
    hostname: str
    proof_expires_at: int
    not_before: int
    expires_at: int
    max_requests: int
    max_bytes: int
    policy_version: str
    nonce: str
    signature: str

    def payload(self) -> bytes:
        values = asdict(self)
        values.pop("signature")
        return json.dumps(
            values, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")


class GrantIssuer:
    """Stateless HMAC signature, stateful proof/revocation verification."""

    def __init__(self, registry: OwnershipRegistry, secret: bytes):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("A private >=256-bit signing key is required")
        self._registry = registry
        self._secret = secret

    def issue(
        self, proof: VerifiedProof, job_id: str, *,
        now: int | None = None, ttl_seconds: int = 300,
        max_requests: int = 40, max_bytes: int = 1_000_000,
    ) -> ScanGrant:
        job_id = _identifier(job_id)
        current = int(time.time()) if now is None else int(now)
        self._registry.check(proof, now=current)
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("Grant TTL must be between 1 and 300 seconds")
        if not 1 <= max_requests <= 100 or not 1 <= max_bytes <= 2_000_000:
            raise ValueError("Invalid job limits")
        unsigned = ScanGrant(
            proof.tenant_id, job_id, proof.id, proof.hostname, proof.expires_at, current,
            min(current + ttl_seconds, proof.expires_at),
            max_requests, max_bytes, "gateway-v1", secrets.token_hex(16), "",
        )
        return ScanGrant(**{**asdict(unsigned), "signature": self._sign(unsigned.payload())})

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def require_active(
        self, grant: ScanGrant, *, tenant_id: str, job_id: str,
        now: int | None = None,
    ) -> None:
        current = int(time.time()) if now is None else int(now)
        if (
            not isinstance(grant, ScanGrant)
            or not isinstance(grant.signature, str)
            or not hmac.compare_digest(self._sign(grant.payload()), grant.signature)
        ):
            raise ProofError("Invalid or tampered scan grant")
        if (
            grant.tenant_id != _identifier(tenant_id)
            or grant.job_id != _identifier(job_id)
            or grant.policy_version != "gateway-v1"
            or current < grant.not_before
            or current >= grant.expires_at
        ):
            raise ProofError("Scan grant tenant, job, policy or TTL mismatch")
        self._registry.check(
            VerifiedProof(
                grant.proof_id, grant.tenant_id, grant.hostname, grant.proof_expires_at
            ),
            now=current,
        )
