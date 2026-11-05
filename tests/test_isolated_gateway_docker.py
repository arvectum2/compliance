"""Two-container Docker E2E: no-network Chromium + nftables Python gateway."""
from __future__ import annotations

import json
import os

import pytest

from arvectum_compliance.adapters.isolated_bridge import run_isolated_fixture

pytestmark = pytest.mark.skipif(
    os.environ.get("COMPLIANCE_DOCKER_E2E") != "1",
    reason="Requires explicitly built kernel-isolated gateway image",
)


@pytest.mark.parametrize("fixture", ("consent.html", "attack.html", "inconclusive.html"))
def test_browser_through_actual_firewall_gateway(fixture):
    report = run_isolated_fixture(fixture, timeout_s=70)
    assert report.source_host == "compliance-fixture.invalid"
    assert report.baseline.phase == "baseline"
    blob = json.dumps(report.to_dict())
    for canary in ("SECRET", "NEVER_SEND_ME", "token="):
        assert canary not in blob
    if fixture == "consent.html":
        assert report.rejected is not None and report.accepted is not None
    else:
        assert report.rejected is None and report.accepted is None
    if fixture == "attack.html":
        hosts = {item.host for item in report.baseline.blocked_requests}
        assert {"127.0.0.1", "169.254.169.254", "10.0.0.1"} <= hosts


@pytest.mark.skipif(
    os.environ.get("COMPLIANCE_OWNED_LIVE_E2E") != "1",
    reason="Opt-in owned-domain live browser pilot; never run on default CI",
)
def test_internal_owned_live_document_only():
    from arvectum_compliance.adapters.isolated_bridge import run_isolated_owned

    report = run_isolated_owned(timeout_s=85)
    assert report.source_host == "arvectum.com"
    assert report.baseline.phase == "baseline"
    assert report.rejected is None and report.accepted is None
    assert len(report.source_sha256 or "") == 64


def test_owned_gateway_rejects_unapproved_hosts_without_any_http_fetch():
    """These are denied before pinned fetch; the test never uses external DNS."""
    import subprocess

    requests = [
        {"kind": "fetch", "id": 1, "url": "http://127.0.0.1:443/",
         "method": "GET", "resource_type": "document"},
        {"kind": "fetch", "id": 2, "url": "https://evil.example/",
         "method": "GET", "resource_type": "document"},
        {"kind": "fetch", "id": 3, "url": "https://arvectum.com/",
         "method": "GET", "resource_type": "stylesheet"},
    ]
    job = subprocess.run(
        ["scripts/run-egress-stdio-gateway.sh", "internal-owned"],
        input="".join(json.dumps(x) + "\n" for x in requests),
        capture_output=True, text=True, timeout=25, check=True,
    )
    lines = job.stdout.splitlines()
    assert lines[0] == "FIREWALL_APPLIED"
    assert len(lines) == 4
    assert [json.loads(line) for line in lines[1:]] == [
        {"kind": "reply", "id": idx, "allowed": False}
        for idx in (1, 2, 3)
    ]
