"""Real Docker E2E for signed grant and revocation; fake DNS only."""
from __future__ import annotations

import json
import os

import pytest

from arvectum_compliance.adapters.attested_bridge import run_attested_fixture

pytestmark = pytest.mark.skipif(
    os.environ.get("COMPLIANCE_DOCKER_E2E") != "1",
    reason="Requires pinned Playwright and separately firewalled gateway images",
)


@pytest.mark.parametrize("fixture", ["consent.html", "attack.html", "inconclusive.html"])
def test_two_container_signed_gateway_without_private_key(fixture):
    report, signed_requests = run_attested_fixture(fixture)
    assert signed_requests == 3
    assert report.source_host == "compliance-fixture.invalid"
    assert report.scenario_version == "0.1.0"
    assert report.baseline.phase == "baseline"
    serialized = json.dumps(report.to_dict())
    for canary in ("SECRET_BASELINE", "SECRET_ACCEPT", "SECRET_REJECT", "NEVER_SEND_ME"):
        assert canary not in serialized
    if fixture == "consent.html":
        assert report.rejected is not None and report.accepted is not None
    else:
        assert report.rejected is None and report.accepted is None


def test_domain_revocation_aborts_live_job_before_next_request():
    # The first signed GET may already be in flight. After revocation, the
    # host cannot sign the next request. No success report may be returned.
    with pytest.raises(RuntimeError, match="failed closed"):
        run_attested_fixture("consent.html", revoke_after=1)



def test_tampered_signed_lease_is_rejected_by_container():
    with pytest.raises(RuntimeError):
        run_attested_fixture("consent.html", tamper_lease=True)


def test_tampered_request_permit_never_yields_success_report():
    with pytest.raises(RuntimeError, match="failed closed"):
        run_attested_fixture("consent.html", tamper_permit=True)


def test_offline_browser_denies_iframes_websocket_cors_and_redirect():
    """Synthetic attack page cannot expand authorized network footprint."""
    report, signed_requests = run_attested_fixture("security.html")
    assert 3 <= signed_requests <= 15
    assert report.rejected is None and report.accepted is None
    blocked = {item.host for item in report.baseline.blocked_requests}
    assert "iframe.attacker.example" in blocked
    assert "cdn.attacker.example" in blocked
    assert "cors.attacker.example" in blocked
    # Exact synthetic origin subresource was signed but the gateway
    # refused an upstream 302 and an unapproved CSS media type.
    assert "compliance-fixture.invalid" in blocked
    assert "socket.attacker.example" in blocked
    serialized = json.dumps(report.to_dict())
    for canary in ("WS_CANARY", "CORS_CANARY", "API_CANARY", "POST_CANARY"):
        assert canary not in serialized
