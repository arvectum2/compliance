"""Fail-closed per-request verification in the unprivileged egress container."""
from __future__ import annotations

import threading
from collections.abc import Callable

from arvectum_compliance.adapters.pinned_http import PinnedResponse, fetch_public_http

from .attested_ipc import GatewayAttestor, SignedLease, SignedPermit
from .domain_proof import ProofError
from .gateway_policy import GatewayResult


class AttestedGatewaySession:
    def __init__(
        self, verifier: GatewayAttestor, lease: SignedLease, *,
        fetcher: Callable = fetch_public_http, now: int | None = None,
    ):
        verifier.start(lease, now=now)
        self.verifier = verifier
        self.lease = lease
        self.fetcher = fetcher
        self.requests = 0
        self.used_bytes = 0
        self._lock = threading.Lock()

    def get(
        self, url: str, *, sequence: int, resource_type: str,
        permit: SignedPermit, now: int | None = None,
    ) -> GatewayResult:
        with self._lock:
            self.verifier.require(
                permit, sequence=sequence, url=url, resource_type=resource_type,
                now=now,
            )
            if self.requests >= self.lease.max_requests:
                raise ProofError("Attested job request quota exceeded")
            budget = self.lease.max_bytes - self.used_bytes
            if budget <= 0:
                raise ProofError("Attested job byte quota exceeded")
            self.requests += 1
            response: PinnedResponse = self.fetcher(
                url, timeout_s=8.0, max_bytes=min(budget, 1_000_000),
            )
            if len(response.body) > budget:
                raise ProofError("Attested gateway byte cap exceeded")
            self.used_bytes += len(response.body)
            return GatewayResult(response.status, response.content_type, response.body)
