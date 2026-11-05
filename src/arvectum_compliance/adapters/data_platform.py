"""Opt-in bounded one-hop HTTP integration using Data Platform public contracts.

Not production safe for arbitrary untrusted tenants without network egress isolation.
"""
from __future__ import annotations

from .pinned_http import fetch_public_http


class RestrictedTransport:
    """Static Data Platform transport: pinned public IP; never follows redirects."""

    name = "compliance-pinned-static-http"

    def fetch(self, request):
        from arvectum_data.acquisition import AcquisitionError, PageSnapshot

        try:
            response = fetch_public_http(
                request.url,
                timeout_s=min(request.timeout_s, 12.0),
                max_bytes=min(request.max_bytes, 2_000_000),
            )
            return PageSnapshot(
                requested_url=request.url,
                final_url=request.url,
                status_code=response.status,
                content_type=response.content_type,
                body=response.body,
                headers={},
                rendered=False,
            )
        except (ValueError, OSError) as exc:
            raise AcquisitionError(
                f"Pinned HTTP acquisition failed: {type(exc).__name__}"
            ) from exc


def scan_url(url: str, *, authorized: bool = False, acquisition=None):
    """Scan single public URL; require explicit owner authorization.

    IP pinning is implemented; multi-tenant still needs network egress isolation.
    """
    if not authorized:
        raise PermissionError("Active scanning requires explicit --authorized confirmation")
    from arvectum_data.acquisition import AcquisitionEngine, AcquisitionRequest, RenderMode
    from arvectum_data.acquisition.security import validate_public_url

    from arvectum_compliance.core.scan import scan_html

    validate_public_url(url)
    engine = acquisition or AcquisitionEngine(http=RestrictedTransport(), renderer=None)
    result = engine.acquire(AcquisitionRequest(
        url=url, render_mode=RenderMode.NEVER, timeout_s=12.0, max_bytes=2_000_000,
    ))
    if result.asset.html is None:
        raise ValueError("URL did not return an HTML document")
    return scan_html(url, result.asset.html)
