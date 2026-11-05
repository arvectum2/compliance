"""Opt-in bounded one-hop HTTP integration using Data Platform public contracts.

Not production safe for arbitrary untrusted tenants without network egress isolation.
"""
from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


class _DenyRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("Redirects are disabled for this scan")


class RestrictedTransport:
    name = "compliance-static-http"

    def fetch(self, request):
        from arvectum_data.acquisition import AcquisitionError, PageSnapshot
        from arvectum_data.acquisition.security import validate_public_url

        validate_public_url(request.url)
        opener = build_opener(_DenyRedirect())
        try:
            with opener.open(
                Request(request.url, method="GET",
                        headers={"User-Agent": "ArvectumCompliance/0.1"}),
                timeout=min(request.timeout_s, 12.0),
            ) as response:
                body = response.read(min(request.max_bytes, 2_000_000) + 1)
                if len(body) > min(request.max_bytes, 2_000_000):
                    raise AcquisitionError("Response exceeds 2 MB limit")
                return PageSnapshot(
                    requested_url=request.url,
                    final_url=response.geturl(),
                    status_code=response.status,
                    content_type=response.headers.get("Content-Type", ""),
                    body=body,
                    headers={},
                    rendered=False,
                )
        except (HTTPError, URLError, ValueError, OSError) as exc:
            raise AcquisitionError(
                f"Bounded HTTP acquisition failed: {type(exc).__name__}"
            ) from exc


def scan_url(url: str, *, authorized: bool = False, acquisition=None):
    """Scan single public URL; require explicit owner authorization.

    Adapter remains non-multi-tenant until network egress/DNS pinning is enforced.
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
