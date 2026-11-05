from __future__ import annotations

import socket
from unittest.mock import Mock

import pytest

from arvectum_compliance.adapters.pinned_http import (
    UnsafeOutboundTarget,
    fetch_public_http,
    resolve_public_target,
)


def dns(*addresses: str):
    def resolve(_host, port, *, type):
        assert type == socket.SOCK_STREAM
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in addresses]
    return resolve


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1",
    "169.254.169.254", "0.0.0.0", "::1", "fd00::1", "fe80::1",
    "100.64.1.1",
])
def test_private_dns_rejected(address):
    with pytest.raises(UnsafeOutboundTarget, match="Non-public"):
        resolve_public_target("https://example.com", resolver=dns(address))


def test_mixed_dns_rebind_fails_closed():
    with pytest.raises(UnsafeOutboundTarget, match="Non-public"):
        resolve_public_target("https://example.com", resolver=dns("8.8.8.8", "127.0.0.1"))


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "http://admin:pass@example.com/",
    "http://example.com:2375", "https://example.com:8080", "ftp://example.com",
])
def test_invalid_urls_rejected(url):
    with pytest.raises(UnsafeOutboundTarget):
        resolve_public_target(url, resolver=dns("8.8.8.8"))


def test_public_dns_single_ip_pinned_and_get_only():
    response = Mock(status=200)
    response.read.return_value = b"<html>ok</html>"
    response.getheader.return_value = "text/html"
    conn = Mock()
    conn.getresponse.return_value = response
    target = []
    def factory(item):
        target.append(item)
        return conn
    data = fetch_public_http(
        "https://example.com/path?token=secret",
        resolver=dns("8.8.8.8"),
        connector_factory=factory,
    )
    assert target[0].pinned_ip == "8.8.8.8"
    assert target[0].hostname == "example.com"
    assert data.body == b"<html>ok</html>"
    assert conn._create_connection is not None
    assert conn.request.call_args.args[:2] == ("GET", "/path?token=secret")
    conn.close.assert_called_once()


def test_3xx_never_followed():
    response = Mock(status=302)
    conn = Mock()
    conn.getresponse.return_value = response
    with pytest.raises(UnsafeOutboundTarget, match="Redirect"):
        fetch_public_http(
            "https://example.com", resolver=dns("8.8.8.8"),
            connector_factory=lambda _: conn,
        )
    response.read.assert_not_called()
    conn.close.assert_called_once()


def test_large_response_aborted():
    response = Mock(status=200)
    response.read.return_value = b"x" * 11
    conn = Mock()
    conn.getresponse.return_value = response
    with pytest.raises(UnsafeOutboundTarget, match="cap"):
        fetch_public_http(
            "https://example.com", resolver=dns("8.8.8.8"),
            connector_factory=lambda _: conn, max_bytes=10,
        )
    conn.close.assert_called_once()


def test_tcp_connection_uses_pinned_ip_not_original_hostname(monkeypatch):
    seen = []
    def fake_connect(address, *, timeout, source_address):
        seen.append(address)
        return object()
    monkeypatch.setattr(socket, "create_connection", fake_connect)
    conn = Mock()
    conn.getresponse.return_value.status = 200
    conn.getresponse.return_value.read.return_value = b"ok"
    conn.getresponse.return_value.getheader.return_value = "text/html"
    fetch_public_http(
        "https://example.com/hello",
        resolver=dns("8.8.8.8"),
        connector_factory=lambda target: conn,
    )
    connected = conn._create_connection(("example.com", 443), timeout=8.0)
    assert connected is not None
    assert seen == [("8.8.8.8", 443)]
