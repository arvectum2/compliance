"""Ownership and grant security regressions, no real DNS required."""
from __future__ import annotations

from dataclasses import replace

import pytest

from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.domain_proof import (
    OwnershipRegistry,
    ProofError,
    canonical_hostname,
)

NOW = 1_800_000_000


def verified():
    registry = OwnershipRegistry()
    challenge = registry.issue("tenant_A", "Example.COM.", now=NOW)
    proof = registry.confirm(
        "tenant_A", challenge.id,
        lambda name: [challenge.record_value] if name == challenge.record_name else [],
        now=NOW + 1,
    )
    return registry, challenge, proof


def test_exact_dns_txt_success_and_normalization():
    registry, challenge, proof = verified()
    assert proof.hostname == "example.com"
    assert challenge.record_name == "_arvectum-compliance.example.com"
    assert challenge.record_value.startswith("arvectum-compliance-v1=")
    registry.check(proof, now=NOW + 2)


def test_challenge_can_only_be_consumed_once():
    registry, challenge, _proof = verified()
    with pytest.raises(ProofError, match="consumed"):
        registry.confirm(
            "tenant_A", challenge.id, lambda _name: [challenge.record_value], now=NOW + 3,
        )


def test_txt_mismatch_does_not_consume():
    registry = OwnershipRegistry()
    challenge = registry.issue("tenant_A", "example.com", now=NOW)
    with pytest.raises(ProofError, match="not found"):
        registry.confirm("tenant_A", challenge.id, lambda _: ["invalid"], now=NOW + 1)
    result = registry.confirm(
        "tenant_A", challenge.id, lambda _: [challenge.record_value], now=NOW + 2,
    )
    assert result.hostname == "example.com"


def test_other_tenant_cannot_use_or_revoke_challenge():
    registry, challenge, proof = verified()
    with pytest.raises(ProofError):
        registry.confirm("tenant_B", challenge.id, lambda _: [challenge.record_value], now=NOW + 2)
    with pytest.raises(ProofError):
        registry.revoke("tenant_B", proof.id)
    registry.check(proof, now=NOW + 3)


def test_revocation_blocks_existing_proof():
    registry, challenge, proof = verified()
    registry.revoke("tenant_A", challenge.id)
    with pytest.raises(ProofError, match="no longer"):
        registry.check(proof, now=NOW + 5)


def test_expired_challenge_refused():
    registry = OwnershipRegistry()
    ch = registry.issue("tenant_A", "example.com", now=NOW)
    with pytest.raises(ProofError):
        registry.confirm("tenant_A", ch.id, lambda _: [ch.record_value], now=NOW + 901)


@pytest.mark.parametrize("hostname", [
    "127.0.0.1", "localhost", "https://example.com", "*example.com",
    "example.com:443", "example.com/path", "user@example.com",
    ".example.com", "bad..example.com", "two .example.com", "",
])
def test_invalid_hostname_refused(hostname):
    with pytest.raises(ProofError):
        canonical_hostname(hostname)


def test_grant_signed_bounded_and_tenant_job_bound():
    registry, _challenge, proof = verified()
    issuer = GrantIssuer(registry, b"S" * 32)
    grant = issuer.issue(proof, "job_01", now=NOW + 2)
    assert grant.hostname == "example.com"
    assert grant.expires_at < proof.expires_at
    issuer.require_active(grant, tenant_id="tenant_A", job_id="job_01", now=NOW + 3)
    with pytest.raises(ProofError):
        issuer.require_active(grant, tenant_id="tenant_B", job_id="job_01", now=NOW + 3)
    with pytest.raises(ProofError):
        issuer.require_active(grant, tenant_id="tenant_A", job_id="job_02", now=NOW + 3)


def test_tampering_and_expiry_rejected():
    registry, challenge, proof = verified()
    issuer = GrantIssuer(registry, b"T" * 32)
    grant = issuer.issue(proof, "job_01", now=NOW + 2)
    with pytest.raises(ProofError):
        issuer.require_active(replace(grant, hostname="other.example.com"),
                              tenant_id="tenant_A", job_id="job_01", now=NOW + 3)
    with pytest.raises(ProofError):
        issuer.require_active(grant, tenant_id="tenant_A", job_id="job_01",
                              now=grant.expires_at)
    registry.revoke("tenant_A", challenge.id)
    with pytest.raises(ProofError):
        issuer.require_active(grant, tenant_id="tenant_A", job_id="job_01", now=NOW + 4)


def test_no_weak_secret_or_excessive_limits():
    registry, _challenge, proof = verified()
    with pytest.raises(ValueError):
        GrantIssuer(registry, b"too short")
    issuer = GrantIssuer(registry, b"T" * 32)
    with pytest.raises(ValueError):
        issuer.issue(proof, "job_01", now=NOW, ttl_seconds=1000)
    with pytest.raises(ValueError):
        issuer.issue(proof, "job_01", now=NOW, max_requests=10000)
