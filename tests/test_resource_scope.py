from __future__ import annotations

import pytest

from arvectum_compliance.service.resource_scope import allowed_same_origin

BASE = "https://example.com"


@pytest.mark.parametrize("resource,url", [
    ("document", BASE + "/"),
    ("stylesheet", BASE + "/assets/site.css"),
    ("script", BASE + "/_next/static/chunk.js"),
    ("image", BASE + "/assets/logo.webp"),
    ("image", BASE + "/favicon.ico"),
    ("font", BASE + "/assets/font.woff2"),
])
def test_only_same_origin_static_assets_accepted(resource, url):
    assert allowed_same_origin("example.com", url, resource_type=resource)


@pytest.mark.parametrize("resource,url", [
    ("document", BASE + "/contact"),
    ("stylesheet", BASE + "/api/export.css"),
    ("script", BASE + "/admin/app.js"),
    ("image", BASE + "/private/image.png"),
    ("image", BASE + "/assets/../image.png"),
    ("image", BASE + "/assets//image.png"),
    ("image", BASE + "/assets/%2e%2e/secret.png"),
    ("image", BASE + "/a%2fb.png"),
    ("image", BASE + "/logo.png?token=SECRET"),
    ("image", "https://cdn.example.com/logo.png"),
    ("script", "https://example.com.attacker.net/file.js"),
    ("image", "http://example.com/logo.png"),
    ("image", "https://user:pass@example.com/logo.png"),
    ("image", "https://example.com:8443/logo.png"),
    ("xhr", BASE + "/site.js"),
    ("fetch", BASE + "/site.js"),
    ("iframe", BASE + "/site.html"),
    ("websocket", BASE + "/site.js"),
])
def test_block_ambiguous_or_active_subresources(resource, url):
    assert not allowed_same_origin("example.com", url, resource_type=resource)


def test_non_get_is_denied_regardless_of_static_extension():
    assert not allowed_same_origin(
        "example.com", BASE + "/site.css", resource_type="stylesheet", method="POST",
    )


def test_invalid_hostname_denied():
    assert not allowed_same_origin("localhost", "https://localhost/logo.png",
                                   resource_type="image")
