from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from arvectum_compliance.service.domain_proof import ProofError
from arvectum_compliance.service.tenant_auth import TenantAuth

NOW = 1800000000
ALL = frozenset({"domain:verify", "scan:create", "domain:revoke"})


def test_token_hashed_and_durable(tmp_path):
    path = tmp_path / "access.db"
    auth = TenantAuth(path)
    token = auth.issue("tenant_A", scopes=ALL, now=NOW)
    assert token.startswith("acp_") and len(token) >= 40
    assert token.encode() not in path.read_bytes()
    assert os.stat(path).st_mode & 0o077 == 0
    p = TenantAuth(path).require(token, "scan:create", now=NOW + 1)
    assert p.tenant_id == "tenant_A" and p.scopes == ALL


def test_scope_denied_and_unknown_token(tmp_path):
    auth = TenantAuth(tmp_path / "access.db")
    token = auth.issue("tenant_A", scopes=frozenset({"domain:verify"}), now=NOW)
    with pytest.raises(ProofError):
        auth.require(token, "scan:create", now=NOW + 1)
    with pytest.raises(ProofError):
        auth.require("acp_invalid", "domain:verify", now=NOW + 1)


def test_expiry_revocation_and_invalid_limits(tmp_path):
    auth = TenantAuth(tmp_path / "access.db")
    token = auth.issue("tenant_A", scopes=ALL, ttl=3, now=NOW)
    auth.require(token, "scan:create", now=NOW + 2)
    with pytest.raises(ProofError):
        auth.require(token, "scan:create", now=NOW + 3)
    token = auth.issue("tenant_A", scopes=ALL, now=NOW)
    auth.revoke(token)
    with pytest.raises(ProofError):
        auth.require(token, "scan:create", now=NOW + 1)
    with pytest.raises(ValueError):
        auth.issue("tenant_A", scopes=frozenset({"admin"}), now=NOW)
    with pytest.raises(ValueError):
        auth.issue("tenant_A", scopes=ALL, ttl=0, now=NOW)


def test_tenant_quota_shared_across_tokens_and_restarts(tmp_path):
    path = tmp_path / "access.db"
    auth = TenantAuth(path)
    token_a = auth.issue("tenant_A", scopes=ALL, ttl=7200, now=NOW)
    token_b = auth.issue("tenant_A", scopes=ALL, ttl=7200, now=NOW)
    a = auth.require(token_a, "domain:verify", now=NOW)
    b = auth.require(token_b, "domain:verify", now=NOW)
    auth.charge(a, "domain:verify", limit=2, now=NOW)
    TenantAuth(path).charge(b, "domain:verify", limit=2, now=NOW + 1)
    with pytest.raises(ProofError, match="quota"):
        auth.charge(a, "domain:verify", limit=2, now=NOW + 2)
    auth.charge(a, "domain:verify", limit=2, now=NOW + 3600)


def test_cross_tenant_quota_independent(tmp_path):
    auth = TenantAuth(tmp_path / "access.db")
    a = auth.require(auth.issue("t_A", scopes=ALL, now=NOW), "scan:create", now=NOW)
    b = auth.require(auth.issue("t_B", scopes=ALL, now=NOW), "scan:create", now=NOW)
    auth.charge(a, "scan:create", limit=1, now=NOW)
    auth.charge(b, "scan:create", limit=1, now=NOW)
    with pytest.raises(ProofError):
        auth.charge(a, "scan:create", limit=1, now=NOW + 1)


def test_atomic_quota_under_concurrency(tmp_path):
    auth = TenantAuth(tmp_path / "access.db")
    principal = auth.require(
        auth.issue("tenant_A", scopes=ALL, now=NOW), "scan:create", now=NOW,
    )
    def take(_):
        try:
            TenantAuth(auth.path).charge(principal, "scan:create", limit=4, now=NOW)
            return True
        except ProofError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        result = list(pool.map(take, range(16)))
    assert result.count(True) == 4


def test_unsafe_store_refused(tmp_path):
    auth = TenantAuth(tmp_path / "access.db")
    os.chmod(auth.path, 0o644)
    with pytest.raises(ProofError):
        TenantAuth(auth.path)
    os.chmod(auth.path, 0o600)
    link = tmp_path / "alias.db"
    link.symlink_to(auth.path)
    with pytest.raises(ProofError):
        TenantAuth(link)
