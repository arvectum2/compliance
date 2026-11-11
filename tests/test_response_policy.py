"""Signed v2 media-type and redirect defense, independent of HTTP connector."""
from __future__ import annotations

import pytest

from arvectum_compliance.service.domain_proof import ProofError
from arvectum_compliance.service.response_policy import require_safe_response


@pytest.mark.parametrize(("resource", "mime"), [
    ("document", "text/html; charset=utf-8"),
    ("document", "application/xhtml+xml"),
    ("stylesheet", "text/css; charset=UTF-8"),
    ("script", "application/javascript"),
    ("script", "text/javascript"),
    ("image", "image/png"),
    ("image", "image/svg+xml"),
    ("font", "font/woff2"),
    ("font", "application/font-woff"),
])
def test_expected_resource_mime_is_accepted(resource, mime):
    require_safe_response(200, mime, resource_type=resource)


@pytest.mark.parametrize(("resource", "mime"), [
    ("document", "application/json"),
    ("document", "text/plain"),
    ("document", "application/octet-stream"),
    ("document", ""),
    ("stylesheet", "text/html"),
    ("stylesheet", "application/javascript"),
    ("script", "text/html"),
    ("script", "application/json"),
    ("image", "text/html"),
    ("image", "application/octet-stream"),
    ("font", "application/zip"),
    ("fetch", "text/html"),
    ("xhr", "application/json"),
    ("iframe", "text/html"),
    ("document", "text/html\nSet-Cookie: SECRET"),
])
def test_untrusted_content_type_is_refused(resource, mime):
    with pytest.raises(ProofError):
        require_safe_response(200, mime, resource_type=resource)


@pytest.mark.parametrize("status", [0, 101, 201, 204, 206, 301, 302, 307, 308, 400, 404, 500, True])
def test_redirect_partial_or_non_200_cannot_reach_browser(status):
    with pytest.raises(ProofError):
        require_safe_response(status, "text/html", resource_type="document")
