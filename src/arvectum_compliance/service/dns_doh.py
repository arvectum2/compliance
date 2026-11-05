"""Conservative dual-provider DNS-over-HTTPS TXT ownership lookup.

Both TLS-authenticated providers must return exactly the same TXT record
set. No arbitrary endpoints, redirects, query types, or URL paths permitted.
DNS-over-HTTPS is not DNSSEC; independent deployment security review remains.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

from .domain_proof import ProofError, canonical_hostname

_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)
_CHUNKS = re.compile(r'(?:"[A-Za-z0-9_=.\-+/]+"\s*)+\Z')
_CHUNK = re.compile(r'"([A-Za-z0-9_=.\-+/]+)"')
_MAX_BYTES = 16_384


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProofError("DNS-over-HTTPS redirect refused")


def _extract_answer(body: bytes, requested: str) -> set[str]:
    if len(body) > _MAX_BYTES:
        raise ProofError("DNS-over-HTTPS response too large")
    try:
        data = json.loads(body)
    except (UnicodeError, ValueError) as exc:
        raise ProofError("Invalid DNS-over-HTTPS response") from exc
    if not isinstance(data, dict) or type(data.get("Status")) is not int:
        raise ProofError("Malformed DNS-over-HTTPS response")
    if data["Status"] == 3 and not data.get("Answer"):
        return set()
    if data["Status"] != 0:
        raise ProofError("DNS-over-HTTPS lookup failed")
    answer = data.get("Answer", [])
    if not isinstance(answer, list) or len(answer) > 64:
        raise ProofError("Invalid DNS-over-HTTPS answer set")
    found: set[str] = set()
    for record in answer:
        if not isinstance(record, dict) or record.get("type") != 16:
            continue
        name, value = record.get("name"), record.get("data")
        if not isinstance(name, str) or name.lower().rstrip(".") != requested:
            raise ProofError("DNS-over-HTTPS response name mismatch")
        if not isinstance(value, str) or len(value) > 1024:
            raise ProofError("Invalid DNS-over-HTTPS TXT value")
        if not _CHUNKS.fullmatch(value):
            raise ProofError("Unexpected DNS TXT encoding")
        parts = _CHUNK.findall(value)
        text = "".join(parts)
        if not text or len(text) > 512:
            raise ProofError("Invalid DNS TXT length")
        found.add(text)
    return found


def lookup_doh_quorum_txt(
    record_name: str,
    *,
    fetch: Callable[[urllib.request.Request], bytes] | None = None,
) -> list[str]:
    """Two TLS-authenticated recursive resolvers; neither answer alone suffices."""
    prefix = "_arvectum-compliance."
    if not isinstance(record_name, str) or not record_name.startswith(prefix):
        raise ProofError("Invalid ownership DNS record")
    fqdn = prefix + canonical_hostname(record_name[len(prefix):])
    opener = urllib.request.build_opener(_NoRedirect())

    def default_fetch(request: urllib.request.Request) -> bytes:
        try:
            with opener.open(request, timeout=5.0) as response:
                if response.status != 200 or response.headers.get(
                    "Content-Type", ""
                ).lower().split(";")[0].strip() not in (
                    "application/json", "application/dns-json"
                ):
                    raise ProofError("Invalid DNS-over-HTTPS HTTP response")
                body = response.read(_MAX_BYTES + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise ProofError("DNS-over-HTTPS request failed") from exc
        return body

    fetcher = fetch or default_fetch
    snapshots: list[set[str]] = []
    for endpoint in _ENDPOINTS:
        query = urllib.parse.urlencode({"name": fqdn, "type": "TXT"})
        request = urllib.request.Request(
            endpoint + "?" + query,
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "ArvectumCompliance/0.1",
            },
        )
        snapshots.append(_extract_answer(fetcher(request), fqdn))
    if not snapshots[0] or snapshots[0] != snapshots[1]:
        raise ProofError("Ownership TXT missing or disagrees between DoH providers")
    return sorted(snapshots[0])
