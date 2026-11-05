"""Strict DNS TXT ownership challenge; no external lookups in the domain model.

The resolver must be a trusted server-side DNS TXT provider. The result of a
DNS lookup is not a credential and does not provide tenant authentication.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

_DOMAIN_LABEL = re.compile(r"(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z")
_TXT_PREFIX = "arvectum-compliance-v1="
_MAX_TTL = 15 * 60


class ProofError(ValueError):
    """Fail-closed ownership verification error."""


def canonical_hostname(host: str) -> str:
    """Normalize an exact DNS hostname, rejecting IPs, wildcards and URLs."""
    if not isinstance(host, str) or not host or host != host.strip():
        raise ProofError("Invalid hostname")
    if any(x in host for x in ("/", ":", "@", "*", "\\", "%", "?", "#")):
        raise ProofError("Only a DNS hostname is accepted")
    raw = host.rstrip(".")
    try:
        candidate = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ProofError("Invalid DNS hostname") from exc
    if len(candidate) > 253 or "." not in candidate or all(
        part.isdigit() for part in candidate.split(".")
    ):
        raise ProofError("Fully-qualified domain is required")
    if any(not _DOMAIN_LABEL.fullmatch(part) for part in candidate.split(".")):
        raise ProofError("Invalid DNS label")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    raise ProofError("IP literals cannot prove DNS ownership")


@dataclass(frozen=True, slots=True)
class PendingProof:
    id: str
    tenant_id: str
    hostname: str
    record_name: str
    record_value: str
    expires_at: int


@dataclass(frozen=True, slots=True)
class VerifiedProof:
    id: str
    tenant_id: str
    hostname: str
    expires_at: int


@dataclass(slots=True)
class _Challenge:
    tenant_id: str
    hostname: str
    digest: str
    expires_at: int
    verified: bool = False
    revoked: bool = False


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", value):
        raise ProofError("Invalid opaque identifier")
    return value


class OwnershipRegistry:
    """Nonpersistent reference model; use a transactional store in production."""

    def __init__(self) -> None:
        self._state: dict[str, _Challenge] = {}
        self._lock = threading.RLock()

    def issue(self, tenant_id: str, hostname: str, *, now: int | None = None) -> PendingProof:
        tenant_id = _identifier(tenant_id)
        hostname = canonical_hostname(hostname)
        issued = int(time.time()) if now is None else int(now)
        challenge_id = secrets.token_hex(16)
        secret = secrets.token_urlsafe(32)
        digest = hashlib.sha256(secret.encode("ascii")).hexdigest()
        expires = issued + _MAX_TTL
        with self._lock:
            self._state[challenge_id] = _Challenge(tenant_id, hostname, digest, expires)
        return PendingProof(
            challenge_id, tenant_id, hostname, f"_arvectum-compliance.{hostname}",
            f"{_TXT_PREFIX}{challenge_id}.{secret}", expires,
        )

    def confirm(
        self, tenant_id: str, proof_id: str,
        txt_lookup: Callable[[str], list[str] | tuple[str, ...]],
        *, now: int | None = None,
    ) -> VerifiedProof:
        tenant_id = _identifier(tenant_id)
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            challenge = self._state.get(proof_id)
            if challenge is None or challenge.tenant_id != tenant_id:
                raise ProofError("Proof unavailable")
            if challenge.revoked or challenge.verified or current >= challenge.expires_at:
                raise ProofError("Proof expired, revoked or consumed")
            record_name = f"_arvectum-compliance.{challenge.hostname}"
            records = txt_lookup(record_name)
            if not isinstance(records, (list, tuple)) or len(records) > 64:
                raise ProofError("Invalid DNS TXT lookup result")
            matches = False
            for record in records:
                if not isinstance(record, str) or len(record) > 512:
                    raise ProofError("Invalid DNS TXT record")
                prefix = f"{_TXT_PREFIX}{proof_id}."
                if record.startswith(prefix):
                    value = record[len(prefix):]
                    candidate = hashlib.sha256(value.encode("utf-8")).hexdigest()
                    matches |= hmac.compare_digest(candidate, challenge.digest)
            if not matches:
                raise ProofError("Domain challenge not found")
            challenge.verified = True
            return VerifiedProof(proof_id, tenant_id, challenge.hostname, challenge.expires_at)

    def check(self, proof: VerifiedProof, *, now: int | None = None) -> None:
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            state = self._state.get(proof.id)
            if (
                state is None or state.revoked or not state.verified
                or current >= state.expires_at
                or state.tenant_id != proof.tenant_id
                or state.hostname != proof.hostname
                or state.expires_at != proof.expires_at
            ):
                raise ProofError("Verified domain ownership is no longer active")

    def revoke(self, tenant_id: str, proof_id: str) -> None:
        tenant_id = _identifier(tenant_id)
        with self._lock:
            state = self._state.get(proof_id)
            if state is None or state.tenant_id != tenant_id:
                raise ProofError("Proof unavailable")
            state.revoked = True
