"""Authenticated verified-domain root-only HTTPS smoke via isolated gateway.

No arbitrary URL or fake DNS input. A genuine persisted domain proof and
tenant token must be checked by the trusted control plane before Docker runs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import subprocess
import time
from dataclasses import asdict
from pathlib import Path

from arvectum_compliance.adapters.isolated_bridge import _BoundedLines, _stop

from .attested_ipc import HostAttestor
from .attestor_keys import AttestorIdentity
from .attestor_rotation import attestor_scan_guard
from .domain_proof import ProofError
from .verified_jobs import VerifiedScanService

ROOT = Path(__file__).resolve().parents[3]
MAX_REPLY = 1_600_000


def run_verified_root(
    service: VerifiedScanService,
    identity: AttestorIdentity,
    token: str,
    proof_id: str,
    job_id: str,
    *,
    timeout_seconds: int = 45,
    runner: Path | None = None,
) -> dict[str, object]:
    """Run with a shared lock preventing concurrent local key rotation."""
    with attestor_scan_guard(identity):
        return _run_verified_root_locked(
            service, identity, token, proof_id, job_id,
            timeout_seconds=timeout_seconds, runner=runner,
        )


def _run_verified_root_locked(
    service: VerifiedScanService,
    identity: AttestorIdentity,
    token: str,
    proof_id: str,
    job_id: str,
    *,
    timeout_seconds: int = 45,
    runner: Path | None = None,
) -> dict[str, object]:
    """Read only exact verified domain root; return hash/count/status, never HTML."""
    if not 10 <= timeout_seconds <= 90:
        raise ValueError("Invalid verified smoke timeout")
    grant = service.authorize_scan(token, proof_id, job_id)
    service.proofs.require_dns_verified(grant.tenant_id, grant.proof_id)
    signer = HostAttestor(service.issuer, identity.private)
    lease = signer.lease(grant)
    root_url = f"https://{grant.hostname}/"
    deadline = time.monotonic() + timeout_seconds
    env = {**os.environ, "COMPLIANCE_ATTEST_PUBLIC_KEY_FILE": str(identity.public_path)}
    worker = subprocess.Popen(
        [str(runner or ROOT / "scripts/run-egress-attested-verified.sh")],
        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0,
    )
    lines = _BoundedLines(worker)
    try:
        if lines.next(deadline, 100) != b"FIREWALL_APPLIED\n":
            raise ProofError("Gateway firewall not initialized")
        assert worker.stdin is not None
        worker.stdin.write(
            (json.dumps({"kind": "lease", "lease": asdict(lease)}) + "\n").encode()
        )
        worker.stdin.flush()
        if lines.next(deadline, 100) != b'{"kind":"ready"}\n':
            raise ProofError("Gateway lease was not accepted")
        # Minted only AFTER the gateway is ready. TTL <=3sec.
        permit = signer.permit(
            grant, lease, sequence=1, url=root_url, resource_type="document",
        )
        worker.stdin.write(
            (json.dumps({
                "kind": "fetch", "id": 1, "url": root_url,
                "method": "GET", "resource_type": "document",
                "permit": asdict(permit),
            }) + "\n").encode()
        )
        worker.stdin.flush()
        response = json.loads(lines.next(deadline, MAX_REPLY))
        if (
            not isinstance(response, dict)
            or set(response) != {
                "kind", "id", "allowed", "status", "content_type", "body_b64"
            }
            or response["kind"] != "reply" or type(response["id"]) is not int
            or response["id"] != 1 or response["allowed"] is not True
            or type(response["status"]) is not int or response["status"] != 200
            or not isinstance(response["content_type"], str)
            or not response["content_type"].lower().startswith("text/html")
            or not isinstance(response["body_b64"], str)
            or len(response["body_b64"]) > 1_400_000
        ):
            raise ProofError("Verified root probe denied or malformed")
        try:
            raw = base64.b64decode(response["body_b64"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ProofError("Malformed gateway HTML framing") from exc
        if not 1 <= len(raw) <= grant.max_bytes:
            raise ProofError("Response outside verified byte budget")
        # A mid-request revocation cannot be reported as successful.
        service.issuer.require_active(
            grant, tenant_id=grant.tenant_id, job_id=grant.job_id,
        )
        if worker.poll() not in (None, 0):
            raise ProofError("Gateway terminated unexpectedly")
        return {
            "hostname": grant.hostname,
            "http_status": 200,
            "html_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "job_id": grant.job_id,
            "policy": "gateway-v2",
            "domain_verified": True,
        }
    finally:
        lines.close()
        _stop(worker)
