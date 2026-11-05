"""Exact-host, signed-scope, bounded egress behavior (no real network)."""
from __future__ import annotations

from dataclasses import replace
from unittest.mock import Mock

import pytest

from arvectum_compliance.adapters.pinned_http import PinnedResponse, UnsafeOutboundTarget
from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.domain_proof import OwnershipRegistry, ProofError
from arvectum_compliance.service.gateway_policy import GatewaySession

NOW = 1_800_000_000


def session(*, requests=2, budget=12, fetcher=None):
    registry = OwnershipRegistry()
    challenge = registry.issue("tenant_1", "example.com", now=NOW)
    verified = registry.confirm("tenant_1", challenge.id,
                                lambda _name: [challenge.record_value], now=NOW + 1)
    issuer = GrantIssuer(registry, b"K" * 32)
    grant = issuer.issue(verified, "job_1", now=NOW + 2,
                         max_requests=requests, max_bytes=budget)
    calls = []

    def fake_fetch(url, **opts):
        calls.append((url, opts))
        return PinnedResponse(200, "text/html", b"ok")

    policy = GatewaySession(
        issuer, grant, tenant_id="tenant_1", job_id="job_1",
        fetcher=fetcher or fake_fetch,
    )
    return policy, calls, registry, challenge, issuer, grant


def test_exact_verified_https_get():
    gateway, calls, *_rest = session()
    assert gateway.get("https://example.com/", now=NOW + 3).body == b"ok"
    assert gateway.get("https://EXAMPLE.COM:443/path", now=NOW + 4).status == 200
    assert gateway.usage == (2, 4)
    assert calls[0][1]["max_bytes"] == 12
    assert calls[1][1]["max_bytes"] == 10
    with pytest.raises(ProofError, match="budget"):
        gateway.get("https://example.com/", now=NOW + 5)


@pytest.mark.parametrize("url", [
    "https://sub.example.com/", "https://example.com.attacker.invalid/",
    "https://other.example.com/", "http://example.com/",
    "https://example.com:8443/", "https://user:pass@example.com/",
    "file:///etc/passwd", "https://127.0.0.1/",
    "https://example.com.evil.example/", "https://example.com@attacker.invalid/",
])
def test_out_of_scope_never_calls_transport(url):
    gateway, calls, *_rest = session()
    with pytest.raises(ProofError):
        gateway.get(url, now=NOW + 3)
    assert calls == []


def test_cross_tenant_grant_and_job_rejected():
    gateway, _calls, _reg, _ch, issuer, grant = session()
    assert gateway.usage == (0, 0)
    with pytest.raises(ProofError):
        GatewaySession(issuer, grant, tenant_id="tenant_2",
                       job_id="job_1").get("https://example.com", now=NOW + 3)
    with pytest.raises(ProofError):
        GatewaySession(issuer, grant, tenant_id="tenant_1",
                       job_id="job_2").get("https://example.com", now=NOW + 3)


def test_tampered_signature_rejected_without_fetch():
    _gateway, calls, _reg, _ch, issuer, grant = session()
    edited = replace(grant, max_bytes=9999)
    with pytest.raises(ProofError):
        GatewaySession(issuer, edited, tenant_id="tenant_1", job_id="job_1",
                       fetcher=lambda *_a, **_k: calls.append("leak")).get(
            "https://example.com", now=NOW + 3,
        )
    assert calls == []


def test_revocation_stops_already_issued_job():
    gateway, _calls, registry, challenge, *_ = session()
    gateway.get("https://example.com/", now=NOW + 3)
    registry.revoke("tenant_1", challenge.id)
    with pytest.raises(ProofError):
        gateway.get("https://example.com/", now=NOW + 4)


def test_byte_budget_is_shared_across_requests():
    gateway, calls, *_rest = session(requests=5, budget=3)
    gateway.get("https://example.com", now=NOW + 3)
    with pytest.raises(UnsafeOutboundTarget):
        def overlong(_url, **_opts):
            raise UnsafeOutboundTarget("Response exceeds configured byte cap")
        gateway._fetcher = overlong
        gateway.get("https://example.com", now=NOW + 4)
    assert gateway.usage[0] == 2
    assert gateway.usage[1] == 2
    gateway._fetcher = lambda _url, **_opts: PinnedResponse(200, "text/html", b"!")
    gateway.get("https://example.com", now=NOW + 5)
    assert gateway.usage == (3, 3)
    with pytest.raises(ProofError, match="byte budget"):
        gateway.get("https://example.com", now=NOW + 6)


def test_expired_job_never_calls_transport():
    gateway, calls, _reg, _ch, _issuer, grant = session()
    with pytest.raises(ProofError):
        gateway.get("https://example.com/", now=grant.expires_at)
    assert calls == []


def test_oversized_url_refused():
    gateway, calls, *_ = session()
    with pytest.raises(ProofError):
        gateway.get("https://example.com/" + "x" * 3000, now=NOW + 3)
    assert not calls


@pytest.mark.parametrize(("url", "resource"), [
    ("https://example.com/api/data", "document"),
    ("https://example.com/contact", "document"),
    ("https://example.com/image.png?access_token=secret", "image"),
    ("https://example.com/admin/app.js", "script"),
    ("https://example.com/site.css", "xhr"),
    ("https://example.com/assets/../image.png", "image"),
])
def test_signed_v2_gateway_rejects_non_static_or_ambiguous_paths(url, resource):
    registry = OwnershipRegistry()
    pending = registry.issue("tenant_1", "example.com", now=NOW)
    proof = registry.confirm("tenant_1", pending.id,
                             lambda _: [pending.record_value], now=NOW + 1)
    issuer = GrantIssuer(registry, b"K" * 32)
    grant = issuer.issue(proof, "job_v2", now=NOW + 2, policy_version="gateway-v2")
    fetch = Mock()
    gateway = GatewaySession(
        issuer, grant, tenant_id="tenant_1", job_id="job_v2", fetcher=fetch,
    )
    with pytest.raises(ProofError, match="static-only"):
        gateway.get(url, resource_type=resource, now=NOW + 3)
    fetch.assert_not_called()


def test_signed_v2_gateway_permits_only_expected_same_origin_static_get():
    registry = OwnershipRegistry()
    pending = registry.issue("tenant_1", "example.com", now=NOW)
    proof = registry.confirm("tenant_1", pending.id,
                             lambda _: [pending.record_value], now=NOW + 1)
    issuer = GrantIssuer(registry, b"K" * 32)
    grant = issuer.issue(proof, "job_v2", now=NOW + 2, policy_version="gateway-v2")
    def fake_fetch(url, **opts):
        assert url.endswith("/assets/site.css")
        return PinnedResponse(200, "text/css", b"body{}")
    gateway = GatewaySession(
        issuer, grant, tenant_id="tenant_1", job_id="job_v2", fetcher=fake_fetch,
    )
    assert gateway.get(
        "https://example.com/assets/site.css", resource_type="stylesheet",
        now=NOW + 3,
    ).body == b"body{}"
