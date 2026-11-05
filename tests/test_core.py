from __future__ import annotations

import json
from pathlib import Path

import pytest

from arvectum_compliance import scan_html

FIXTURES = Path(__file__).parent / "fixtures"
URL = "https://example.com/contact"


def test_good_form_has_no_review_findings() -> None:
    report = scan_html(URL, (FIXTURES / "good.html").read_text())
    assert report.findings == ()
    assert report.signals.forms == 1
    assert report.signals.personal_data_forms == 1
    assert report.signals.policy_links == 1
    assert report.signals.consent_controls == 1


def test_review_form_is_conservative_and_redacted() -> None:
    report = scan_html(URL, (FIXTURES / "review.html").read_text())
    assert [f.rule_id for f in report.findings] == [
        "WEB-CONSENT-SIGNAL", "WEB-EXTERNAL-FORM", "WEB-POLICY-LINK",
    ]
    assert all(f.status == "review" and f.rule_version == "1.0.0" for f in report.findings)
    serialized = json.dumps(report.to_dict(), ensure_ascii=False)
    assert "SECRET_CANARY" not in serialized
    assert "+7 999" not in serialized
    assert "not findings of legal infringement" in serialized
    assert report.signals.external_actions == 1


def test_no_contact_form_is_not_a_violation() -> None:
    report = scan_html(URL, "<html><body>Hello</body></html>")
    assert report.findings == ()
    assert report.signals.forms == 0


def test_url_query_stripped_from_evidence() -> None:
    report = scan_html("https://example.com/?secret_token=CANARY#x", "<form></form>")
    assert report.source_url == "https://example.com/"
    assert "CANARY" not in json.dumps(report.to_dict())


@pytest.mark.parametrize("url", ["file:///etc/passwd", "javascript:alert(1)", "not a url",
                                "https://admin:password@example.com/"])
def test_unsafe_source_url_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        scan_html(url, "<html></html>")


def test_large_html_rejected() -> None:
    with pytest.raises(ValueError, match="limit"):
        scan_html(URL, "x" * 2_000_001)


def test_identical_scans_have_identical_json() -> None:
    html = (FIXTURES / "review.html").read_text()
    assert scan_html(URL, html).to_dict() == scan_html(URL, html).to_dict()
