from __future__ import annotations

import json
from copy import deepcopy

import pytest

from arvectum_compliance.adapters.browser_fixture import parse_fixture_json


def sample():
    return {
        "schema_version": "1.0",
        "fixture": "consent.html",
        "source_host": "compliance-fixture.invalid",
        "browser": "chromium",
        "network_mode": "none",
        "scenario_version": "0.1.0",
        "generated_at": "2026-11-05T08:00:00.000Z",
        "browser_version": "146.0.0.0",
        "source_sha256": "a" * 64,
        "baseline": {
            "phase": "baseline",
            "requests": [
                {"host": "compliance-fixture.invalid", "count": 1},
                {"host": "tracker.example", "count": 1},
            ],
            "cookies": [{"host": "compliance-fixture.invalid", "count": 1}],
            "blocked": [{"host": "tracker.example", "count": 1}],
        },
        "rejected": {
            "phase": "reject",
            "requests": [{"host": "metrics.example", "count": 1}],
            "cookies": [],
            "blocked": [{"host": "metrics.example", "count": 1}],
        },
        "accepted": None,
        "limitations": ["Fixture only"],
    }


def test_fixture_converts_to_core_and_preserves_blocked_as_distinct():
    data = parse_fixture_json(json.dumps(sample()))
    assert data.baseline.requests[-1].host == "tracker.example"
    assert data.baseline.blocked_requests[0].host == "tracker.example"
    assert data.rejected is not None
    assert data.rejected.blocked_requests[0].count == 1
    assert {r.code for r in data.reviews} == {
        "COOKIE-PRE-CONSENT", "CROSS-HOST-AFTER-REJECT",
    }
    assert data.accepted is None


@pytest.mark.parametrize("change", [
    {"network_mode": "bridge"},
    {"schema_version": "1.1"},
    {"source_host": "127.0.0.1"},
    {"fixture": "../.env"},
    {"cookie_values": ["LEAK"]},
])
def test_reject_unexpected_or_untrusted_output(change):
    data = sample()
    data.update(change)
    with pytest.raises(ValueError):
        parse_fixture_json(json.dumps(data))


def test_reject_secret_injected_into_host_count():
    data = sample()
    data["baseline"]["cookies"][0]["value"] = "SECRET"
    with pytest.raises(ValueError):
        parse_fixture_json(json.dumps(data))


def test_reject_duplicate_and_bogus_counts():
    data = sample()
    data["baseline"]["requests"].append({"host": "tracker.example", "count": 1})
    with pytest.raises(ValueError):
        parse_fixture_json(json.dumps(data))
    data = deepcopy(sample())
    data["baseline"]["requests"][0]["count"] = -1
    with pytest.raises(ValueError):
        parse_fixture_json(json.dumps(data))


def test_reject_oversized_output():
    with pytest.raises(ValueError):
        parse_fixture_json("x" * 60_001)


def test_reject_wrong_phase():
    data = sample()
    data["baseline"]["phase"] = "accept"
    with pytest.raises(ValueError, match="mismatch"):
        parse_fixture_json(json.dumps(data))


def test_timestamp_must_be_timezone_aware():
    data = sample()
    data["generated_at"] = "2026-11-05T08:00:00"
    with pytest.raises(ValueError, match="timestamp"):
        parse_fixture_json(json.dumps(data))
