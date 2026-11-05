"""Fixture-only stdio gateway bridge for a no-network Chromium Docker worker.

An operator cannot supply arbitrary targets: the browser target is hardcoded
to .invalid, DNS proof is synthetic, and the fetcher reads local test HTML.
This exercises the live IPC protocol without permitting live-site browsing.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import selectors
import subprocess
import time
from pathlib import Path

from arvectum_compliance.adapters.browser_fixture import parse_fixture_json
from arvectum_compliance.adapters.pinned_http import PinnedResponse
from arvectum_compliance.core.browser_evidence import ConsentObservation
from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.domain_proof import OwnershipRegistry
from arvectum_compliance.service.gateway_policy import GatewaySession

ROOT = Path(__file__).resolve().parents[3]
ORIGIN = "https://compliance-fixture.invalid/"
FIXTURES = {"consent.html", "attack.html", "inconclusive.html"}
ALLOWED_RESOURCES = {"document", "fetch", "xhr", "image", "script", "stylesheet"}


def _gateway_for_fixture(fixture: str) -> GatewaySession:
    page = (ROOT / "tests/browser-fixtures" / fixture).read_bytes()
    if len(page) > 200_000:
        raise ValueError("Fixture HTML too large")
    registry = OwnershipRegistry()
    challenge = registry.issue("internal_qa", "compliance-fixture.invalid")
    # This DNS proof is NOT from the public DNS. It exists only for offline QA.
    proof = registry.confirm(
        "internal_qa", challenge.id, lambda _name: [challenge.record_value],
    )
    issuer = GrantIssuer(registry, secrets.token_bytes(32))
    grant = issuer.issue(
        proof, "fixture_job", ttl_seconds=120,
        max_requests=80, max_bytes=1_000_000,
    )

    def fixture_fetch(url: str, **_options) -> PinnedResponse:
        if url == ORIGIN:
            return PinnedResponse(200, "text/html; charset=utf-8", page)
        # Subresources from the verified fixture origin get empty responses
        # in the simulator; all other hosts fail at the signed gateway policy.
        return PinnedResponse(204, "text/plain", b"")

    return GatewaySession(
        issuer, grant, tenant_id="internal_qa", job_id="fixture_job",
        fetcher=fixture_fetch,
    )


def _gateway_reply(message: object, gateway: GatewaySession) -> dict[str, object]:
    if not isinstance(message, dict) or set(message) != {
        "kind", "id", "url", "method", "resource_type"
    }:
        raise ValueError("Invalid worker IPC request envelope")
    item_id = message["id"]
    if type(item_id) is not int or not 1 <= item_id <= 120:
        raise ValueError("Invalid worker request ID")
    reply: dict[str, object] = {"kind": "reply", "id": item_id, "allowed": False}
    if (
        message["kind"] != "fetch"
        or message["method"] != "GET"
        or not isinstance(message["resource_type"], str)
        or message["resource_type"] not in ALLOWED_RESOURCES
        or not isinstance(message["url"], str)
    ):
        return reply
    try:
        response = gateway.get(message["url"])
    except (ValueError, OSError, RuntimeError):
        return reply
    return {
        **reply, "allowed": True, "status": response.status,
        "content_type": response.content_type,
        "body_b64": base64.b64encode(response.body).decode("ascii"),
    }


def run_fixture_bridge(
    fixture: str,
    *,
    runner: Path | None = None,
    timeout_seconds: int = 45,
) -> tuple[ConsentObservation, tuple[int, int]]:
    """End-to-end Docker run, no network to fixture or any external hostname."""
    if fixture not in FIXTURES or timeout_seconds not in range(10, 61):
        raise ValueError("Only approved offline fixtures and bounded timeout are allowed")
    runner = runner or ROOT / "scripts/run-browser-bridge-fixture.sh"
    gateway = _gateway_for_fixture(fixture)
    proc = subprocess.Popen(
        [str(runner), fixture],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    output_bytes = 0
    buffered = b""
    result = None
    seen_ids: set[int] = set()
    deadline = time.monotonic() + timeout_seconds
    selector = selectors.DefaultSelector()
    try:
        assert proc.stdin is not None and proc.stdout is not None
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("Isolated browser exceeded wall-time limit")
            if not selector.select(left):
                raise TimeoutError("Isolated browser did not respond")
            block = os.read(proc.stdout.fileno(), 65536)
            if not block:
                break
            output_bytes += len(block)
            if output_bytes > 500_000:
                raise ValueError("Browser IPC output exceeded limit")
            buffered += block
            while b"\n" in buffered:
                line, buffered = buffered.split(b"\n", 1)
                if len(line) > 80_000:
                    raise ValueError("Oversized worker control message")
                message = json.loads(line)
                if not isinstance(message, dict) or "kind" not in message:
                    raise ValueError("Invalid worker IPC message")
                if message["kind"] == "fetch":
                    item_id = message.get("id")
                    if type(item_id) is not int or not 1 <= item_id <= 120:
                        raise ValueError("Invalid worker request ID")
                    if item_id in seen_ids:
                        raise ValueError("Replayed worker request ID")
                    seen_ids.add(item_id)
                    if len(seen_ids) > 120:
                        raise ValueError("Too many worker requests")
                    reply = _gateway_reply(message, gateway)
                    proc.stdin.write(
                        (json.dumps(reply, separators=(",", ":")) + "\n").encode("utf-8")
                    )
                    proc.stdin.flush()
                elif message["kind"] == "result":
                    if result is not None or set(message) != {"kind", "report"}:
                        raise ValueError("Repeated or malformed worker result")
                    result = parse_fixture_json(json.dumps(message["report"]))
                    if message["report"]["fixture"] != fixture:
                        raise ValueError("Fixture mismatch")
                else:
                    raise ValueError("Worker reported an error or unexpected IPC message")
        if proc.wait(timeout=3) != 0 or result is None:
            raise RuntimeError("Isolated browser failed without a validated report")
        return result, gateway.usage
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3)
        if proc.stdin is not None:
            proc.stdin.close()
        if proc.stdout is not None:
            proc.stdout.close()
