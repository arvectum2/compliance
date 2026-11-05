"""Deliberately narrow same-origin static subresource policy.

This is a prerequisite for future verified-domain browser runs, not a
general crawler. No credential, query, API, iframe, XHR or POST is allowed.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from .domain_proof import ProofError, canonical_hostname

_STATIC_SUFFIXES = {
    "stylesheet": frozenset({".css"}),
    "script": frozenset({".js", ".mjs"}),
    "image": frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif"}),
    "font": frozenset({".woff", ".woff2", ".ttf", ".otf"}),
}
_DISALLOWED = re.compile(r"[%\\\x00-\x1f\x7f]")
_FORBIDDEN_PATHS = re.compile(
    r"(^|/)(?:api|admin|login|auth|logout|private|account|graphql|wp-admin)(?:/|$)",
    re.IGNORECASE,
)


def allowed_same_origin(
    verified_hostname: str, url: str, *,
    resource_type: str, method: str = "GET",
) -> bool:
    """No subresource request may expand the signed exact-host grant."""
    try:
        host = canonical_hostname(verified_hostname)
        if not isinstance(url, str) or len(url) > 2048 or method != "GET":
            return False
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https" or parsed.port not in (None, 443)
            or parsed.username is not None or parsed.password is not None
            or not parsed.hostname or canonical_hostname(parsed.hostname) != host
            or parsed.query or parsed.fragment
        ):
            return False
        path = parsed.path or "/"
        # No URL encoding, ambiguous separators, dot segments or control chars.
        if _DISALLOWED.search(path) or unquote(path) != path:
            return False
        if not path.startswith("/") or "//" in path or _FORBIDDEN_PATHS.search(path):
            return False
        if any(segment in (".", "..") for segment in path.split("/")):
            return False
        if resource_type == "document":
            return path == "/"
        suffixes = _STATIC_SUFFIXES.get(resource_type)
        if not suffixes:
            return False
        return PurePosixPath(path).suffix.lower() in suffixes
    except (ValueError, ProofError):
        return False
