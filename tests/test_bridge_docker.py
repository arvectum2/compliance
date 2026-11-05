"""End-to-end stdio broker across the no-network Chromium Docker boundary."""
from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path

import pytest

from arvectum_compliance.adapters.fixture_bridge import run_fixture_bridge

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    os.environ.get("COMPLIANCE_DOCKER_E2E") != "1",
    reason="Run only in the pinned, isolated Docker security workflow",
)


@pytest.mark.parametrize("fixture", ["consent.html", "attack.html", "inconclusive.html"])
def test_real_browser_to_signed_gateway_to_mocked_fixture(fixture):
    report, usage = run_fixture_bridge(fixture)
    expected = sha256((ROOT / "tests/browser-fixtures" / fixture).read_bytes()).hexdigest()
    assert report.source_sha256 == expected
    assert report.source_host == "compliance-fixture.invalid"
    assert report.baseline.phase == "baseline"
    assert usage[0] == 3  # only the 3 verified document requests passed the broker
    assert usage[1] > 0
    output = json.dumps(report.to_dict())
    for forbidden in ("SECRET_BASELINE", "SECRET_REJECT", "SECRET_ACCEPT",
                      "LEAK", "NEVER_SEND_ME", "latest/meta-data", "token="):
        assert forbidden not in output
    if fixture == "consent.html":
        assert report.rejected is not None and report.accepted is not None
        assert any(x.host == "metrics.example" for x in report.rejected.blocked_requests)
        assert any(x.host == "metrics.example" for x in report.accepted.blocked_requests)
    elif fixture == "attack.html":
        assert report.rejected is None and report.accepted is None
        blocked = {x.host for x in report.baseline.blocked_requests}
        assert {"10.0.0.1", "127.0.0.1", "169.254.169.254"} <= blocked
    else:
        assert report.rejected is None and report.accepted is None
