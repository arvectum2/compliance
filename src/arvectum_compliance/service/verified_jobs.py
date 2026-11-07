"""Trusted internal control plane: token -> REAL DNS TXT -> signed scan grant.

No fake DNS acknowledgement is used by the default implementation.
The test-only resolver injection must never be exposed to external clients.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from .authorization import GrantIssuer, ScanGrant
from .dns_doh import lookup_doh_quorum_txt
from .domain_proof import PendingProof, VerifiedProof
from .sqlite_proof import SqliteOwnershipRegistry
from .tenant_auth import TenantAuth

if TYPE_CHECKING:
    from .job_ledger import JobLedger

DNSLookup = Callable[[str], list[str]]


class VerifiedScanService:
    """Not a network API: authenticate in a trusted host application first."""

    def __init__(
        self,
        auth: TenantAuth,
        proofs: SqliteOwnershipRegistry,
        issuer: GrantIssuer,
        *,
        dns_lookup: DNSLookup | None = None,
    ):
        self.auth = auth
        self.proofs = proofs
        self.issuer = issuer
        self.dns_lookup = dns_lookup or lookup_doh_quorum_txt
        self._real_dns_lookup = dns_lookup is None

    def issue_challenge(
        self, access_token: str, hostname: str, *, now: int | None = None,
    ) -> PendingProof:
        current = int(time.time()) if now is None else int(now)
        principal = self.auth.require(access_token, "domain:verify", now=current)
        self.auth.charge(principal, "domain:verify", limit=10, now=current)
        return self.proofs.issue(principal.tenant_id, hostname, now=current)

    def confirm_challenge(
        self, access_token: str, challenge_id: str, *, now: int | None = None,
    ) -> VerifiedProof:
        current = int(time.time()) if now is None else int(now)
        principal = self.auth.require(access_token, "domain:verify", now=current)
        self.auth.charge(principal, "domain:verify", limit=10, now=current)
        # Real TXT lookup by default, not caller-provided TXT strings.
        return self.proofs.confirm(
            principal.tenant_id, challenge_id, self.dns_lookup,
            now=current,
            verification_method="doh-quorum" if self._real_dns_lookup else "offline-test",
        )

    def authorize_scan(
        self, access_token: str, proof_id: str, job_id: str, *,
        now: int | None = None,
    ) -> ScanGrant:
        current = int(time.time()) if now is None else int(now)
        principal = self.auth.require(access_token, "scan:create", now=current)
        self.auth.charge(principal, "scan:create", limit=30, now=current)
        proof = self.proofs.get_verified(principal.tenant_id, proof_id, now=current)
        return self.issuer.issue(
            proof, job_id, now=current, ttl_seconds=180,
            max_requests=40, max_bytes=1_000_000,
            policy_version="gateway-v2",
        )

    def queue_scan(
        self, access_token: str, proof_id: str, job_id: str,
        ledger: JobLedger, *, now: int | None = None,
    ) -> ScanGrant:
        """Authenticated proof-to-job queue. No HTTP worker is started."""
        grant = self.authorize_scan(
            access_token, proof_id, job_id, now=now,
        )
        ledger.enqueue(
            grant, issuer=self.issuer, proofs=self.proofs, now=now,
        )
        return grant

    def revoke_domain(
        self, access_token: str, proof_id: str, *, now: int | None = None,
    ) -> None:
        current = int(time.time()) if now is None else int(now)
        principal = self.auth.require(access_token, "domain:revoke", now=current)
        self.auth.charge(principal, "domain:revoke", limit=20, now=current)
        self.proofs.revoke(principal.tenant_id, proof_id)
