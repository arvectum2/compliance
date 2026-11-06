"""Ed25519-attested per-request bridge to a network-isolated gateway.

Host signs only AFTER verifying an HMAC grant against the current persistent
proof state. Container sees PUBLIC verification key only; revocation takes
effect before the next signed request, not retroactively mid-flight.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .authorization import GrantIssuer, ScanGrant
from .domain_proof import ProofError, canonical_hostname
from .resource_scope import allowed_same_origin

_HEX = re.compile(r"[a-f0-9]{32,128}\Z")


def _bytes(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _envelope_fields(data: object, fields: frozenset[str]) -> dict:
    if not isinstance(data, dict) or frozenset(data) != fields:
        raise ProofError("Malformed authorization envelope")
    return data


_LEASE_FIELDS = frozenset({
    "tenant_id", "job_id", "hostname", "proof_id", "proof_expires_at",
    "not_before", "expires_at", "max_requests", "max_bytes",
    "policy_version", "nonce", "signature",
})
_PERMIT_FIELDS = frozenset({
    "lease_nonce", "sequence", "url_digest", "resource_type",
    "expires_at", "signature",
})


@dataclass(frozen=True, slots=True)
class SignedLease:
    tenant_id: str
    job_id: str
    hostname: str
    proof_id: str
    proof_expires_at: int
    not_before: int
    expires_at: int
    max_requests: int
    max_bytes: int
    policy_version: str
    nonce: str
    signature: str

    def payload(self) -> bytes:
        data = asdict(self)
        del data["signature"]
        return _bytes(data)

    @classmethod
    def parse(cls, data: object) -> SignedLease:
        return cls(**_envelope_fields(data, _LEASE_FIELDS))


@dataclass(frozen=True, slots=True)
class SignedPermit:
    lease_nonce: str
    sequence: int
    url_digest: str
    resource_type: str
    expires_at: int
    signature: str

    def payload(self) -> bytes:
        data = asdict(self)
        del data["signature"]
        return _bytes(data)

    @classmethod
    def parse(cls, data: object) -> SignedPermit:
        return cls(**_envelope_fields(data, _PERMIT_FIELDS))


class HostAttestor:
    """Only host control plane receives private Ed25519 signing key."""

    def __init__(self, issuer: GrantIssuer, key: Ed25519PrivateKey):
        self.issuer = issuer
        self.key = key

    def lease(self, grant: ScanGrant, *, now: int | None = None) -> SignedLease:
        current = int(time.time()) if now is None else int(now)
        self.issuer.require_active(
            grant, tenant_id=grant.tenant_id, job_id=grant.job_id, now=current,
        )
        if grant.policy_version != "gateway-v2":
            raise ProofError("Only gateway-v2 is accepted")
        unsigned = SignedLease(
            grant.tenant_id, grant.job_id, grant.hostname, grant.proof_id,
            grant.proof_expires_at, grant.not_before, grant.expires_at,
            grant.max_requests, grant.max_bytes, grant.policy_version,
            grant.nonce, "",
        )
        return SignedLease(**{
            **asdict(unsigned), "signature": self.key.sign(unsigned.payload()).hex(),
        })

    def permit(
        self, grant: ScanGrant, lease: SignedLease, *,
        sequence: int, url: str, resource_type: str, now: int | None = None,
    ) -> SignedPermit:
        current = int(time.time()) if now is None else int(now)
        # Proof checked against database ON EVERY REQUEST, including revocation.
        self.issuer.require_active(
            grant, tenant_id=grant.tenant_id, job_id=grant.job_id, now=current,
        )
        if (
            lease.signature != self.lease(grant, now=current).signature
            or type(sequence) is not int
            or not 1 <= sequence <= grant.max_requests
            or not allowed_same_origin(
                grant.hostname, url, resource_type=resource_type,
            )
        ):
            raise ProofError("Refused out-of-scope request")
        unsigned = SignedPermit(
            lease.nonce, sequence, hashlib.sha256(url.encode("utf-8")).hexdigest(),
            resource_type, min(current + 3, lease.expires_at), "",
        )
        return SignedPermit(**{
            **asdict(unsigned), "signature": self.key.sign(unsigned.payload()).hex(),
        })


class GatewayAttestor:
    """Gateway verifies signatures with public key and sequence without secrets."""

    def __init__(self, key: Ed25519PublicKey):
        self.key = key
        self.lease: SignedLease | None = None
        self.last_sequence = 0

    def _verify(self, signature: str, payload: bytes) -> None:
        if not isinstance(signature, str) or not re.fullmatch(r"[a-f0-9]{128}", signature):
            raise ProofError("Invalid authorization signature")
        try:
            self.key.verify(bytes.fromhex(signature), payload)
        except (InvalidSignature, ValueError) as exc:
            raise ProofError("Invalid authorization signature") from exc

    def start(self, lease: SignedLease, *, now: int | None = None) -> None:
        current = int(time.time()) if now is None else int(now)
        self._verify(lease.signature, lease.payload())
        if (
            self.lease is not None or lease.policy_version != "gateway-v2"
            or type(lease.not_before) is not int or type(lease.expires_at) is not int
            or type(lease.proof_expires_at) is not int
            or current < lease.not_before or current >= lease.expires_at
            or lease.expires_at > lease.proof_expires_at
            or lease.expires_at - lease.not_before > 300
            or type(lease.max_requests) is not int
            or not 1 <= lease.max_requests <= 100
            or type(lease.max_bytes) is not int
            or not 1 <= lease.max_bytes <= 2_000_000
            or not isinstance(lease.nonce, str) or not _HEX.fullmatch(lease.nonce)
            or canonical_hostname(lease.hostname) != lease.hostname
        ):
            raise ProofError("Rejected invalid gateway lease")
        self.lease = lease

    def require(
        self, permit: SignedPermit, *, sequence: int, url: str,
        resource_type: str, now: int | None = None,
    ) -> SignedLease:
        lease = self.lease
        current = int(time.time()) if now is None else int(now)
        if lease is None:
            raise ProofError("No signed lease initialized")
        self._verify(permit.signature, permit.payload())
        if (
            current < lease.not_before or current >= lease.expires_at
            or current >= permit.expires_at
            or permit.expires_at > min(current + 3, lease.expires_at)
            or type(sequence) is not int
            or sequence != self.last_sequence + 1
            or sequence > lease.max_requests
            or permit.sequence != sequence
            or permit.lease_nonce != lease.nonce
            or permit.url_digest != hashlib.sha256(url.encode("utf-8")).hexdigest()
            or permit.resource_type != resource_type
            or not allowed_same_origin(
                lease.hostname, url, resource_type=resource_type,
            )
        ):
            raise ProofError("Rejected unauthorized gateway request")
        # Consume even if the following HTTP request fails: no replay.
        self.last_sequence = sequence
        return lease
