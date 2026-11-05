"""Control-plane DNS is mocked ONLY in offline tests."""
from __future__ import annotations

from unittest.mock import Mock

import pytest

from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.domain_proof import ProofError
from arvectum_compliance.service.sqlite_proof import SqliteOwnershipRegistry
from arvectum_compliance.service.tenant_auth import TenantAuth
from arvectum_compliance.service.verified_jobs import VerifiedScanService

NOW = 1800000000
SCOPES = frozenset({"domain:verify", "scan:create", "domain:revoke"})


def setup_service(tmp_path):
    auth = TenantAuth(tmp_path / "auth.db")
    proofs = SqliteOwnershipRegistry(tmp_path / "proofs.db")
    issuer = GrantIssuer(proofs, b"Q" * 32)
    published = []
    lookup = Mock(side_effect=lambda _: list(published))
    service = VerifiedScanService(auth, proofs, issuer, dns_lookup=lookup)
    alice = auth.issue("alice", scopes=SCOPES, now=NOW)
    bob = auth.issue("bob", scopes=SCOPES, now=NOW)
    return service, alice, bob, published, lookup


def test_exact_dns_proof_then_signed_grant(tmp_path):
    service, alice, _bob, published, lookup = setup_service(tmp_path)
    challenge = service.issue_challenge(alice, "EXAMPLE.COM", now=NOW)
    assert challenge.record_name == "_arvectum-compliance.example.com"
    with pytest.raises(ProofError, match="not found"):
        service.confirm_challenge(alice, challenge.id, now=NOW + 1)
    lookup.assert_called_with(challenge.record_name)
    published.append(challenge.record_value)
    proof = service.confirm_challenge(alice, challenge.id, now=NOW + 2)
    grant = service.authorize_scan(alice, proof.id, "job_one", now=NOW + 3)
    assert (grant.tenant_id, grant.hostname) == ("alice", "example.com")
    assert grant.policy_version == "gateway-v2"
    service.issuer.require_active(grant, tenant_id="alice", job_id="job_one", now=NOW + 4)


def test_cross_tenant_and_revocation(tmp_path):
    service, alice, bob, published, _lookup = setup_service(tmp_path)
    challenge = service.issue_challenge(alice, "example.com", now=NOW)
    published.append(challenge.record_value)
    with pytest.raises(ProofError):
        service.confirm_challenge(bob, challenge.id, now=NOW + 1)
    proof = service.confirm_challenge(alice, challenge.id, now=NOW + 2)
    with pytest.raises(ProofError):
        service.authorize_scan(bob, proof.id, "job_other", now=NOW + 3)
    grant = service.authorize_scan(alice, proof.id, "job_one", now=NOW + 3)
    service.revoke_domain(alice, proof.id, now=NOW + 4)
    with pytest.raises(ProofError):
        service.issuer.require_active(grant, tenant_id="alice", job_id="job_one", now=NOW + 5)


def test_failed_dns_cannot_authorize(tmp_path):
    service, alice, _bob, _published, _lookup = setup_service(tmp_path)
    challenge = service.issue_challenge(alice, "example.com", now=NOW)
    with pytest.raises(ProofError):
        service.confirm_challenge(alice, challenge.id, now=NOW + 1)
    with pytest.raises(ProofError):
        service.authorize_scan(alice, challenge.id, "job_one", now=NOW + 2)


def test_scope_before_dns_network(tmp_path):
    service, _alice, _bob, _published, lookup = setup_service(tmp_path)
    read_only = service.auth.issue(
        "tenant_1", scopes=frozenset({"scan:create"}), now=NOW,
    )
    with pytest.raises(ProofError):
        service.issue_challenge(read_only, "example.com", now=NOW + 1)
    with pytest.raises(ProofError):
        service.confirm_challenge(read_only, "nonexistent", now=NOW + 2)
    lookup.assert_not_called()


def test_challenge_quota(tmp_path):
    service, alice, _bob, _published, _lookup = setup_service(tmp_path)
    for _ in range(10):
        service.issue_challenge(alice, "example.com", now=NOW)
    with pytest.raises(ProofError, match="quota"):
        service.issue_challenge(alice, "example.com", now=NOW + 1)


def test_default_dns_callback_is_real_lookup_not_fake(tmp_path, monkeypatch):
    from arvectum_compliance.service import verified_jobs

    callback = Mock(side_effect=ProofError("DNS unavailable"))
    monkeypatch.setattr(verified_jobs, "lookup_doh_quorum_txt", callback)
    auth = TenantAuth(tmp_path / "auth.db")
    proofs = SqliteOwnershipRegistry(tmp_path / "proofs.db")
    service = VerifiedScanService(auth, proofs, GrantIssuer(proofs, b"S" * 32))
    token = auth.issue("tenant_A", scopes=SCOPES, now=NOW)
    challenge = service.issue_challenge(token, "example.com", now=NOW)
    with pytest.raises(ProofError, match="DNS unavailable"):
        service.confirm_challenge(token, challenge.id, now=NOW + 1)
    callback.assert_called_once_with(challenge.record_name)
    with pytest.raises(ProofError):
        service.authorize_scan(token, challenge.id, "job_1", now=NOW + 2)
