from __future__ import annotations

import json

import pytest

from arvectum_compliance.core.browser_evidence import (
    PhaseEvidence,
    compare_consent_phases,
)


def test_browser_evidence_redacts_url_params_and_cookie_values() -> None:
    first = PhaseEvidence.from_observations(
        "baseline",
        ["https://tracker.example/pixel?email=alice@example.com&token=SECRET_CANARY",
         "https://tracker.example/other?id=123"],
        [".tracker.example", ".tracker.example"],
    )
    report = compare_consent_phases("https://example.com/?token=CANARY", first)
    data = json.dumps(report.to_dict())
    assert "SECRET_CANARY" not in data
    assert "alice@" not in data
    assert "pixel" not in data
    assert "CANARY" not in data
    assert report.baseline.requests[0].host == "tracker.example"
    assert report.baseline.cookies[0].count == 2
    assert {r.code for r in report.reviews} == {
        "COOKIE-PRE-CONSENT", "CONSENT-REJECT-INCONCLUSIVE",
    }


def test_rejection_cross_host_is_review_not_legal_verdict() -> None:
    baseline = PhaseEvidence.from_observations("baseline", [], [])
    rejected = PhaseEvidence.from_observations(
        "reject", ["https://cdn.example/assets"], [],
    )
    report = compare_consent_phases("https://example.com/", baseline, rejected)
    assert [r.code for r in report.reviews] == ["CROSS-HOST-AFTER-REJECT"]
    assert all(r.status == "review" for r in report.reviews)


def test_no_cookie_and_explicit_rejection_no_review() -> None:
    baseline = PhaseEvidence.from_observations("baseline", [], [])
    rejected = PhaseEvidence.from_observations("reject", ["https://example.com/app"], [])
    report = compare_consent_phases("https://example.com", baseline, rejected)
    assert report.reviews == ()


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "http://admin:pass@example.com", "mailto:foo@example.com",
])
def test_reject_untrusted_network_observation_url(url: str) -> None:
    with pytest.raises(ValueError):
        PhaseEvidence.from_observations("baseline", [url], [])


def test_reject_excessive_observation_volume() -> None:
    with pytest.raises(ValueError, match="cap"):
        PhaseEvidence.from_observations("baseline", ["https://example.com"] * 2001, [])


def test_phase_consistency() -> None:
    rejected = PhaseEvidence.from_observations("reject", [], [])
    with pytest.raises(ValueError, match="mismatch"):
        compare_consent_phases("https://example.com", rejected)
