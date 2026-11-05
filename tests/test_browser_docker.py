"""Explicit, opt-in security E2E against the isolated Chromium container."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from arvectum_compliance.adapters.browser_fixture import parse_fixture_json

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    os.environ.get("COMPLIANCE_DOCKER_E2E") != "1",
    reason="Set COMPLIANCE_DOCKER_E2E=1 after pulling the pinned Playwright image",
)


def docker_fixture(filename: str) -> dict:
    proc = subprocess.run(
        [str(ROOT / "scripts/run-browser-fixture.sh"), filename],
        capture_output=True, text=True, timeout=55, check=True,
    )
    assert "SECRET" not in proc.stdout
    return json.loads(proc.stdout)


def test_consent_phases_are_independently_observed_and_sanitized():
    data = docker_fixture("consent.html")
    report = parse_fixture_json(json.dumps(data))
    assert data["network_mode"] == "none"
    assert report.rejected is not None
    assert report.accepted is not None
    assert report.baseline.cookies
    assert any(x.host == "metrics.example" for x in report.rejected.blocked_requests)
    assert any(x.host == "metrics.example" for x in report.accepted.blocked_requests)


def test_private_metadata_and_cross_origin_are_all_blocked():
    data = docker_fixture("attack.html")
    report = parse_fixture_json(json.dumps(data))
    assert report.baseline
    blocked = {x["host"] for x in data["baseline"]["blocked"]}
    assert "169.254.169.254" in blocked
    assert "127.0.0.1" in blocked
    assert "10.0.0.1" in blocked
    assert "external.example" in blocked
    assert data["rejected"] is None
    assert data["accepted"] is None
    assert "NEVER_SEND_ME" not in json.dumps(data)


def test_submit_like_button_must_not_be_clicked():
    data = docker_fixture("inconclusive.html")
    assert data["accepted"] is None
    assert data["rejected"] is None
    assert "LEAK" not in json.dumps(data)
