"""Bounded exact-domain GET gateway policy. No public server or browser egress."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from urllib.parse import urlsplit

from arvectum_compliance.adapters.pinned_http import PinnedResponse, fetch_public_http

from .authorization import GrantIssuer, ScanGrant
from .domain_proof import ProofError, canonical_hostname


@dataclass(frozen=True, slots=True)
class GatewayResult:
    status: int
    content_type: str
    body: bytes


class GatewaySession:
    """One job, one exact verified hostname, capped requests and total bytes.

    The session must be held server-side, not exposed to untrusted clients.
    """

    def __init__(
        self, issuer: GrantIssuer, grant: ScanGrant, *,
        tenant_id: str, job_id: str, fetcher=fetch_public_http,
    ):
        self._issuer = issuer
        self._grant = grant
        self._tenant_id = tenant_id
        self._job_id = job_id
        self._fetcher = fetcher
        self._requests = 0
        self._bytes = 0
        self._lock = threading.Lock()

    def get(self, url: str, *, now: int | None = None) -> GatewayResult:
        # Lock also covers IO, preventing concurrent requests from bypassing
        # the shared job budget (serialized by design).
        with self._lock:
            self._issuer.require_active(
                self._grant, tenant_id=self._tenant_id, job_id=self._job_id, now=now,
            )
            if not isinstance(url, str) or not 1 <= len(url) <= 2048:
                raise ProofError("Invalid URL length")
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https" or parsed.username is not None
                or parsed.password is not None or not parsed.hostname
            ):
                raise ProofError("Only credential-free HTTPS is allowed")
            try:
                port = parsed.port
                host = canonical_hostname(parsed.hostname)
            except ValueError as exc:
                raise ProofError("Invalid hostname or port") from exc
            if port not in (None, 443) or host != self._grant.hostname:
                raise ProofError("Hostname or port outside exact authorization scope")
            if self._requests >= self._grant.max_requests:
                raise ProofError("Request budget exhausted")
            remaining = self._grant.max_bytes - self._bytes
            if remaining < 1:
                raise ProofError("Response byte budget exhausted")
            self._requests += 1
            response: PinnedResponse = self._fetcher(
                url, timeout_s=8.0, max_bytes=min(remaining, 1_000_000),
            )
            if len(response.body) > remaining:
                raise ProofError("Gateway response exceeded authorized byte budget")
            self._bytes += len(response.body)
            return GatewayResult(response.status, response.content_type, response.body)

    @property
    def usage(self) -> tuple[int, int]:
        with self._lock:
            return self._requests, self._bytes
