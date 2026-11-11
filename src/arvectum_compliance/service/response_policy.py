"""Exact resource-type to HTTP media-type contract for signed gateway v2.

Never allow a fake/buggy transport to smuggle redirects, HTML as a script,
JSON as a document, or opaque binary downloads into Chromium.
"""
from __future__ import annotations

import re

from .domain_proof import ProofError

_MEDIA = {
    "document": frozenset({"text/html", "application/xhtml+xml"}),
    "stylesheet": frozenset({"text/css"}),
    "script": frozenset({
        "text/javascript", "application/javascript",
        "application/x-javascript", "text/ecmascript",
        "application/ecmascript",
    }),
    "image": frozenset({
        "image/png", "image/jpeg", "image/gif", "image/webp",
        "image/avif", "image/svg+xml", "image/x-icon",
        "image/vnd.microsoft.icon",
    }),
    "font": frozenset({
        "font/woff", "font/woff2", "font/ttf", "font/otf",
        "application/font-woff", "application/font-woff2",
    }),
}
_CONTENT_TYPE = re.compile(r"^[\x20-\x7e]{1,200}\Z")


def require_safe_response(
    status: int, content_type: str, *, resource_type: str,
) -> None:
    """Require HTTP 200 with a narrow MIME family, fail closed."""
    if type(status) is not int or status != 200:
        raise ProofError("Non-200 gateway response refused")
    if (
        not isinstance(content_type, str)
        or not _CONTENT_TYPE.fullmatch(content_type)
        or resource_type not in _MEDIA
    ):
        raise ProofError("Unsafe or absent Content-Type")
    mime = content_type.split(";", 1)[0].strip().lower()
    if mime not in _MEDIA[resource_type]:
        raise ProofError("Content-Type not approved for signed resource")
