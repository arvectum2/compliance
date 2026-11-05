from __future__ import annotations

import pytest

from arvectum_compliance.adapters.data_platform import RestrictedTransport, scan_url


def test_no_permission_never_imports_or_sends_network_requests() -> None:
    with pytest.raises(PermissionError):
        scan_url("https://example.com", authorized=False)


def test_restricted_transport_calls_pinned_fetch(monkeypatch) -> None:
    pytest.importorskip("arvectum_data")
    from arvectum_data.acquisition import AcquisitionRequest

    from arvectum_compliance.adapters import data_platform
    from arvectum_compliance.adapters.pinned_http import PinnedResponse

    seen = []
    def fake_fetch(url, **options):
        seen.append((url, options))
        return PinnedResponse(200, "text/html", b"<html>safe</html>")

    monkeypatch.setattr(data_platform, "fetch_public_http", fake_fetch)
    snapshot = RestrictedTransport().fetch(
        AcquisitionRequest(url="https://example.com", max_bytes=200),
    )
    assert snapshot.body == b"<html>safe</html>"
    assert seen[0][1]["max_bytes"] == 200


def test_private_target_rejected_if_data_platform_available() -> None:
    pytest.importorskip("arvectum_data")
    with pytest.raises(ValueError):
        scan_url("http://127.0.0.1", authorized=True)


def test_scan_url_uses_data_platform_contract(monkeypatch) -> None:
    pytest.importorskip("arvectum_data")
    import arvectum_data.acquisition.security as security
    from arvectum_data.acquisition import AcquisitionAttempt, AcquisitionRequest, AcquisitionResult
    from arvectum_data.engine.models import RawAsset

    monkeypatch.setattr(security, "validate_public_url", lambda url: None)

    class Stub:
        def acquire(self, request: AcquisitionRequest):
            assert request.render_mode.value == "never"
            assert request.max_bytes == 2_000_000
            return AcquisitionResult(
                asset=RawAsset(
                    asset_id="fixture",
                    source_url=request.url,
                    html="<form><input type='email' name='email'></form>",
                ),
                attempts=(AcquisitionAttempt(method="fixture", success=True, reason="test"),),
            )

    report = scan_url("https://example.com", authorized=True, acquisition=Stub())
    assert report.signals.personal_data_forms == 1
    assert len(report.findings) == 2
