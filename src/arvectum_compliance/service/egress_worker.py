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

from arvectum_compliance.adapters.pinned_http import PinnedResponse
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
    raise SystemExit("Usage: egress_worker.py fixture <approved-name> | internal-owned")
