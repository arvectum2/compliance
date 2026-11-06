"""Ed25519 attestation checks require neither a network nor real DNS."""
from __future__ import annotations

import secrets
from dataclasses import asdict, replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arvectum_compliance.adapters.pinned_http import PinnedResponse
from arvectum_compliance.service.attested_gateway import AttestedGatewaySession
from arvectum_compliance.service.attested_ipc import (
    GatewayAttestor,
    HostAttestor,
    SignedLease,
    SignedPermit,
)
from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.domain_proof import OwnershipRegistry, ProofError

NOW = 1800000000
ROOT = "https://example.com/"
ASSET = "https://example.com/assets/site.css"


def setup():
    registry = OwnershipRegistry()
    pending = registry.issue("test_tenant", "example.com", now=NOW)
    proof = registry.confirm(
        "test_tenant", pending.id, lambda _: [pending.record_value], now=NOW + 1,
    )
    issuer = GrantIssuer(registry, secrets.token_bytes(32))
    grant = issuer.issue(
        proof, "test_job", now=NOW + 2, policy_version="gateway-v2",
    )
    key = Ed25519PrivateKey.generate()
    host = HostAttestor(issuer, key)
    lease = host.lease(grant, now=NOW + 3)
    verifier = GatewayAttestor(key.public_key())
    return registry, proof, grant, host, lease, verifier


def test_signed_lease_and_permit_authorize_exact_request():
    _registry, _proof, grant, host, lease, verifier = setup()
    session = AttestedGatewaySession(
        verifier, lease, now=NOW + 3,
        fetcher=lambda url, **kw: PinnedResponse(200, "text/html", b"ok"),
    )
    permit = host.permit(
        grant, lease, sequence=1, url=ROOT, resource_type="document", now=NOW + 4,
    )
    assert session.get(
        ROOT, sequence=1, resource_type="document", permit=permit, now=NOW + 4,
    ).body == b"ok"
    assert session.requests == 1 and session.used_bytes == 2


def test_gateway_rejects_wrong_lease_signature_or_wrong_public_key():
    _r, _p, _g, _host, lease, verifier = setup()
    with pytest.raises(ProofError, match="signature"):
        verifier.start(replace(lease, hostname="attacker.example"), now=NOW + 3)
    other = GatewayAttestor(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(ProofError, match="signature"):
        other.start(lease, now=NOW + 3)


def test_invalid_expired_and_v1_leases_refused():
    _r, _p, _g, _host, lease, verifier = setup()
    with pytest.raises(ProofError):
        verifier.start(lease, now=lease.expires_at)
    with pytest.raises(ProofError):
        verifier.start(replace(lease, policy_version="gateway-v1"), now=NOW + 3)


def test_signed_permit_cannot_be_replayed_or_used_for_another_url():
    _r, _p, grant, host, lease, verifier = setup()
    verifier.start(lease, now=NOW + 3)
    permit = host.permit(
        grant, lease, sequence=1, url=ROOT, resource_type="document", now=NOW + 4,
    )
    with pytest.raises(ProofError):
        verifier.require(
            permit, sequence=1, url=ASSET, resource_type="document", now=NOW + 4,
        )
    verifier.require(
        permit, sequence=1, url=ROOT, resource_type="document", now=NOW + 4,
    )
    with pytest.raises(ProofError):
        verifier.require(
            permit, sequence=1, url=ROOT, resource_type="document", now=NOW + 4,
        )


def test_gateway_rejects_tampered_permit_and_expired_permit():
    _r, _p, grant, host, lease, verifier = setup()
    verifier.start(lease, now=NOW + 3)
    permit = host.permit(
        grant, lease, sequence=1, url=ROOT, resource_type="document", now=NOW + 4,
    )
    with pytest.raises(ProofError):
        verifier.require(
            replace(permit, url_digest="0" * 64),
            sequence=1, url=ROOT, resource_type="document", now=NOW + 4,
        )
    with pytest.raises(ProofError):
        verifier.require(
            permit, sequence=1, url=ROOT, resource_type="document",
            now=permit.expires_at,
        )


def test_revocation_prevents_next_host_approval():
    registry, proof, grant, host, lease, verifier = setup()
    verifier.start(lease, now=NOW + 3)
    permit = host.permit(
        grant, lease, sequence=1, url=ROOT, resource_type="document", now=NOW + 4,
    )
    verifier.require(permit, sequence=1, url=ROOT, resource_type="document", now=NOW + 4)
    registry.revoke("test_tenant", proof.id)
    with pytest.raises(ProofError):
        host.permit(
            grant, lease, sequence=2, url=ROOT, resource_type="document",
            now=NOW + 5,
        )


@pytest.mark.parametrize(("url", "resource"), [
    ("https://evil.example/", "document"),
    ("https://example.com/api/secret.js", "script"),
    ("https://example.com/path?token=canary", "document"),
    ("https://example.com/contact", "document"),
    ("http://example.com/", "document"),
    ("https://example.com/assets/a.js", "fetch"),
])
def test_host_cannot_sign_out_of_scope_resource(url, resource):
    _r, _p, grant, host, lease, _v = setup()
    with pytest.raises(ProofError):
        host.permit(
            grant, lease, sequence=1, url=url, resource_type=resource,
            now=NOW + 4,
        )


def test_unexpected_json_fields_fail_closed():
    _r, _p, grant, host, lease, _v = setup()
    with pytest.raises(ProofError):
        SignedLease.parse({**asdict(lease), "override": "yes"})
    permit = host.permit(
        grant, lease, sequence=1, url=ROOT, resource_type="document", now=NOW + 4,
    )
    with pytest.raises(ProofError):
        SignedPermit.parse({**asdict(permit), "secret": "LEAK"})


def test_no_unsigned_permit_can_read_from_gateway():
    _r, _p, grant, host, lease, verifier = setup()
    def fetch(_url, **_kw):
        raise AssertionError("HTTP must never be called for missing permit")
    session = AttestedGatewaySession(verifier, lease, fetcher=fetch, now=NOW + 3)
    valid = host.permit(
        grant, lease, sequence=1, url=ROOT, resource_type="document", now=NOW + 4,
    )
    with pytest.raises(ProofError):
        session.get(
            ROOT, sequence=1, resource_type="document",
            permit=replace(valid, signature="0" * 128), now=NOW + 4,
        )
    assert session.requests == 0
