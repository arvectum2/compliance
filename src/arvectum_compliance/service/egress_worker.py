"""Isolated container-side stdio HTTPS gateway.

Modes are bounded to synthetic fixtures or a single internal-owned site.
The internal mode is deliberately not a public ownership verification API.
GatewaySession performs exact-host and request/byte budget checks in this
network namespace before the pinned HTTPS transport.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arvectum_compliance.adapters.pinned_http import PinnedResponse
from arvectum_compliance.service.attested_gateway import AttestedGatewaySession
from arvectum_compliance.service.attested_ipc import (
    GatewayAttestor,
    SignedLease,
    SignedPermit,
)
from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.domain_proof import OwnershipRegistry
from arvectum_compliance.service.gateway_policy import GatewaySession

FIXTURES = {"consent.html", "attack.html", "inconclusive.html"}
ALLOWED_TYPES = {"document", "script", "stylesheet", "image", "fetch", "xhr"}
OWNED_SITE = "arvectum.com"
FIXTURE_SITE = "compliance-fixture.invalid"
MAX_LINE = 4096
MAX_MESSAGES = 120


def _init_gateway(mode: str, fixture: str | None = None) -> GatewaySession:
    if mode not in {"fixture", "internal-owned"}:
        raise ValueError("Unsupported isolated gateway mode")
    if mode == "fixture":
        if fixture not in FIXTURES:
            raise ValueError("Unapproved fixture")
        html = (Path("/opt/compliance/fixtures") / fixture).read_bytes()
        if len(html) > 200_000:
            raise ValueError("Oversized fixture")
        hostname = FIXTURE_SITE

        def fixture_fetch(url: str, **_opts) -> PinnedResponse:
            if url == f"https://{hostname}/":
                return PinnedResponse(200, "text/html; charset=utf-8", html)
            return PinnedResponse(204, "text/plain", b"")

        fetcher = fixture_fetch
    else:
        if fixture is not None:
            raise ValueError("Internal owned mode does not accept fixture")
        hostname = OWNED_SITE
        fetcher = None
    registry = OwnershipRegistry()
    ch = registry.issue("internal_qa", hostname)
    # This internally scoped QA capability is NOT a verified DNS record;
    # production must replace it with an authenticated real TXT proof.
    proof = registry.confirm("internal_qa", ch.id, lambda _: [ch.record_value])
    issuer = GrantIssuer(registry, secrets.token_bytes(32))
    grant = issuer.issue(proof, "private_gateway_job", ttl_seconds=120,
                         max_requests=60, max_bytes=1_000_000)
    settings = dict(tenant_id="internal_qa", job_id="private_gateway_job")
    if fetcher:
        settings["fetcher"] = fetcher
    return GatewaySession(issuer, grant, **settings)


def handle_fetch(msg: object, gateway: GatewaySession, *, expected_id: int) -> dict:
    if not isinstance(msg, dict) or set(msg) != {
        "kind", "id", "url", "method", "resource_type"
    } or msg["kind"] != "fetch":
        raise ValueError("Malformed IPC envelope")
    if type(msg["id"]) is not int or msg["id"] != expected_id:
        raise ValueError("Unexpected or replayed IPC request ID")
    result: dict[str, object] = {"kind": "reply", "id": msg["id"], "allowed": False}
    if (
        msg["method"] != "GET"
        or not isinstance(msg["resource_type"], str)
        or msg["resource_type"] not in ALLOWED_TYPES
        or not isinstance(msg["url"], str)
    ):
        return result
    try:
        response = gateway.get(
            msg["url"], resource_type=msg["resource_type"],
        )
    except (ValueError, OSError, RuntimeError):
        return result
    if not 200 <= response.status < 300 or len(response.body) > 1_000_000:
        return result
    return {
        **result, "allowed": True, "status": response.status,
        "content_type": response.content_type[:128],
        "body_b64": base64.b64encode(response.body).decode("ascii"),
    }



def _read_attested_public_key() -> Ed25519PublicKey:
    """Container receives public verification key from a read-only Docker bind."""
    path = Path("/run/compliance/attestor.pub")
    if path.is_symlink() or not path.is_file() or path.stat().st_size != 32:
        raise ValueError("Missing independent attestation public key")
    return Ed25519PublicKey.from_public_bytes(path.read_bytes())


def serve_attested_fixture(fixture: str) -> int:
    """Test-only .invalid fixtures, but REAL signed authorization is mandatory."""
    if os.geteuid() != 65532 and os.environ.get("COMPLIANCE_UNIT_TEST") != "1":
        raise RuntimeError("Gateway requires unprivileged service account")
    if fixture not in FIXTURES:
        return 2
    try:
        verifier = GatewayAttestor(_read_attested_public_key())
        line = sys.stdin.buffer.readline(8193)
        if not line or len(line) > 8192:
            return 2
        start = json.loads(line)
        if not isinstance(start, dict) or set(start) != {"kind", "lease"}:
            return 2
        lease = SignedLease.parse(start["lease"])
        if lease.hostname != FIXTURE_SITE:
            return 2
        html = (Path("/opt/compliance/fixtures") / fixture).read_bytes()
        if len(html) > 200_000:
            return 2

        def fixture_fetch(url: str, **_opts) -> PinnedResponse:
            if url == f"https://{FIXTURE_SITE}/":
                return PinnedResponse(200, "text/html; charset=utf-8", html)
            return PinnedResponse(204, "text/plain", b"")

        gateway = AttestedGatewaySession(verifier, lease, fetcher=fixture_fetch)
        sys.stdout.write('{"kind":"ready"}\n')
        sys.stdout.flush()
    except (ValueError, TypeError, OSError):
        return 2
    for sequence, line in enumerate(sys.stdin.buffer, 1):
        if sequence > MAX_MESSAGES or len(line) > 8192:
            return 2
        try:
            msg = json.loads(line)
            if not isinstance(msg, dict) or set(msg) != {
                "kind", "id", "url", "method", "resource_type", "permit"
            } or msg["kind"] != "fetch" or msg["method"] != "GET":
                return 2
            if type(msg["id"]) is not int or msg["id"] != sequence:
                return 2
            permit = SignedPermit.parse(msg["permit"])
            response = gateway.get(
                msg["url"], sequence=sequence,
                resource_type=msg["resource_type"], permit=permit,
            )
            reply = {
                "kind": "reply", "id": sequence, "allowed": True,
                "status": response.status, "content_type": response.content_type[:128],
                "body_b64": base64.b64encode(response.body).decode("ascii"),
            }
        except (ValueError, TypeError, OSError, RuntimeError):
            # Denied: never echo an untrusted URL, token, or proof.
            reply = {"kind": "reply", "id": sequence, "allowed": False}
        sys.stdout.write(json.dumps(reply, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


def _owned_document_only(message: object) -> bool:
    """Manual internal smoke sends exactly one safe document GET per phase."""
    return (
        isinstance(message, dict)
        and set(message) == {"kind", "id", "url", "method", "resource_type"}
        and message["kind"] == "fetch"
        and message["url"] == "https://arvectum.com/"
        and message["method"] == "GET"
        and message["resource_type"] == "document"
    )


def serve(mode: str, fixture: str | None = None) -> int:
    if os.geteuid() != 65532 and os.environ.get("COMPLIANCE_UNIT_TEST") != "1":
        raise RuntimeError("Egress gateway requires restricted UID")
    gateway = _init_gateway(mode, fixture)
    for number, line in enumerate(sys.stdin.buffer, start=1):
        if number > MAX_MESSAGES or len(line) > MAX_LINE:
            return 2
        try:
            msg = json.loads(line)
            if mode == "internal-owned" and not _owned_document_only(msg):
                if (
                    not isinstance(msg, dict)
                    or type(msg.get("id")) is not int
                    or msg["id"] != number
                ):
                    raise ValueError("Invalid internal-only request")
                reply = {"kind": "reply", "id": msg["id"], "allowed": False}
            else:
                reply = handle_fetch(msg, gateway, expected_id=number)
        except (ValueError, TypeError, UnicodeError):
            return 2
        sys.stdout.write(json.dumps(reply, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    # argv allows only exact fixture names or the hardcoded owned domain
    # smoke. Never an arbitrary public user-supplied host.
    argv = sys.argv[1:]
    if len(argv) == 2 and argv[0] == "fixture" and argv[1] in FIXTURES:
        raise SystemExit(serve("fixture", argv[1]))
    if len(argv) == 1 and argv[0] == "internal-owned":
        raise SystemExit(serve("internal-owned"))
    if len(argv) == 2 and argv[0] == "attested-fixture" and argv[1] in FIXTURES:
        raise SystemExit(serve_attested_fixture(argv[1]))
    raise SystemExit("Usage: egress_worker.py fixture <approved-name> | internal-owned")
