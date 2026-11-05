"""IP-pinned HTTP primitive for a FUTURE audited gateway, not production ready."""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit


class UnsafeOutboundTarget(ValueError):
    """Target rejected before or during a controlled fetch."""


@dataclass(frozen=True, slots=True)
class PublicTarget:
    scheme: str
    hostname: str
    port: int
    path: str
    pinned_ip: str


def resolve_public_target(url: str, *, resolver=None) -> PublicTarget:
    """Fail closed on any private DNS address, and pin a single public address."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeOutboundTarget("Absolute HTTP(S) URL required")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeOutboundTarget("Credentials in URL prohibited")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except (ValueError, UnicodeError) as exc:
        raise UnsafeOutboundTarget("Invalid hostname or port") from exc
    if not hostname or len(hostname) > 253 or port not in {80, 443}:
        raise UnsafeOutboundTarget("Unsupported hostname or port")
    lookup = resolver or socket.getaddrinfo
    try:
        answers = lookup(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeOutboundTarget("DNS lookup failed") from exc
    if not 1 <= len(answers) <= 32:
        raise UnsafeOutboundTarget("DNS result count outside limits")
    ips = []
    for answer in answers:
        try:
            ip = ipaddress.ip_address(answer[4][0])
        except ValueError as exc:
            raise UnsafeOutboundTarget("DNS returned invalid IP") from exc
        if isinstance(ip, ipaddress.IPv6Address) and (
            ip.ipv4_mapped is not None or ip.sixtofour is not None
            or ip.teredo is not None
        ):
            raise UnsafeOutboundTarget("Tunneled or IPv4-mapped IPv6 refused")
        if not ip.is_global:
            raise UnsafeOutboundTarget("Non-public IP address refused")
        ips.append(str(ip))
    # Prefer IPv4 when both public A and AAAA exist: no IPv6 route on some hosts.
    ips.sort(key=lambda addr: ipaddress.ip_address(addr).version != 4)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return PublicTarget(parsed.scheme, hostname, port, path, ips[0])


@dataclass(frozen=True, slots=True)
class PinnedResponse:
    status: int
    content_type: str
    body: bytes


def fetch_public_http(
    url: str, *, resolver=None, connector_factory=None,
    timeout_s: float = 8.0, max_bytes: int = 1_000_000,
) -> PinnedResponse:
    """Single GET; no automatic redirects. TLS hostname verification preserved."""
    if not 0 < timeout_s <= 15 or not 0 < max_bytes <= 2_000_000:
        raise ValueError("Invalid resource limits")
    target = resolve_public_target(url, resolver=resolver)
    if connector_factory is not None:
        conn = connector_factory(target)
    elif target.scheme == "https":
        conn = http.client.HTTPSConnection(
            target.hostname, target.port, timeout=timeout_s,
            context=ssl.create_default_context(),
        )
    else:
        conn = http.client.HTTPConnection(
            target.hostname, target.port, timeout=timeout_s,
        )

    # No second DNS lookup: connect to validated IP. HTTPSConnection uses
    # original self.host as TLS SNI and for certificate hostname verification.
    def pinned_connect(_address, timeout=None, source_address=None):
        return socket.create_connection(
            (target.pinned_ip, target.port),
            timeout=timeout_s,
            source_address=source_address,
        )

    conn._create_connection = pinned_connect
    try:
        conn.request(
            "GET", target.path,
            headers={"Host": target.hostname, "User-Agent": "ArvectumCompliance/0.1"},
        )
        response = conn.getresponse()
        if not 200 <= response.status < 300:
            raise UnsafeOutboundTarget("Redirect or non-success status refused")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise UnsafeOutboundTarget("Response exceeds byte cap")
        return PinnedResponse(
            response.status, response.getheader("Content-Type", "")[:200], body,
        )
    finally:
        conn.close()
