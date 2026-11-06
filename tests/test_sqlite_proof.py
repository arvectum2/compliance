from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.domain_proof import ProofError
from arvectum_compliance.service.sqlite_proof import SqliteOwnershipRegistry

NOW = 1_800_000_000


def test_verified_proof_survives_registry_restart_without_plaintext(tmp_path):
    path = tmp_path / "proofs.db"
    reg = SqliteOwnershipRegistry(path)
    issued = reg.issue("team_1", "Example.COM", now=NOW)
    assert os.stat(path).st_mode & 0o077 == 0
    contents = path.read_bytes()
    assert issued.record_value.encode("ascii") not in contents
    assert issued.id.encode("ascii") in contents
    restarted = SqliteOwnershipRegistry(path)
    verified = restarted.confirm("team_1", issued.id,
                                lambda _name: [issued.record_value], now=NOW + 1)
    reg.check(verified, now=NOW + 2)
    issuer = GrantIssuer(restarted, b"X" * 32)
    grant = issuer.issue(verified, "job_1", now=NOW + 2)
    issuer.require_active(grant, tenant_id="team_1", job_id="job_1", now=NOW + 3)
    reg.revoke("team_1", verified.id)
    with pytest.raises(ProofError):
        issuer.require_active(grant, tenant_id="team_1", job_id="job_1", now=NOW + 4)


def test_proof_confirmation_is_atomic_and_single_use(tmp_path):
    registry = SqliteOwnershipRegistry(tmp_path / "proofs.db")
    issued = registry.issue("team_1", "example.com", now=NOW)

    def attempt(_):
        try:
            registry.confirm("team_1", issued.id,
                             lambda _name: [issued.record_value], now=NOW + 2)
            return True
        except ProofError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(12)))
    assert outcomes.count(True) == 1


def test_cross_tenant_and_expiry(tmp_path):
    registry = SqliteOwnershipRegistry(tmp_path / "proofs.db")
    issued = registry.issue("team_1", "example.com", now=NOW)
    with pytest.raises(ProofError):
        registry.confirm("team_2", issued.id, lambda _: [issued.record_value], now=NOW + 2)
    with pytest.raises(ProofError):
        registry.confirm("team_1", issued.id, lambda _: [issued.record_value], now=NOW + 901)


def test_refuse_world_readable_database(tmp_path):
    path = tmp_path / "insecure.db"
    sqlite3.connect(path).close()
    os.chmod(path, 0o644)
    with pytest.raises(ProofError, match="private"):
        SqliteOwnershipRegistry(path)


def test_reject_symlink_database(tmp_path):
    source = tmp_path / "real.db"
    SqliteOwnershipRegistry(source)
    alias = tmp_path / "alias.db"
    alias.symlink_to(source)
    with pytest.raises(ProofError, match="Unsafe"):
        SqliteOwnershipRegistry(alias)


def test_legacy_proofs_do_not_turn_into_production_ownership(tmp_path):
    import sqlite3

    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE domain_proofs(
                id TEXT PRIMARY KEY, tenant TEXT, hostname TEXT,
                challenge_hash TEXT, expires_at INTEGER, status TEXT
            )
        """)
    import os
    os.chmod(path, 0o600)
    reg = SqliteOwnershipRegistry(path)  # schema migration, defaults to "legacy"
    challenge = reg.issue("tenant_1", "example.com", now=NOW)
    verified = reg.confirm(
        "tenant_1", challenge.id, lambda _: [challenge.record_value],
        now=NOW + 1,
    )
    reg.check(verified, now=NOW + 2)
    with pytest.raises(ProofError, match="Real DNS"):
        reg.require_dns_verified("tenant_1", verified.id, now=NOW + 2)


def test_real_doh_method_accepts_but_offline_method_never_does(tmp_path):
    reg = SqliteOwnershipRegistry(tmp_path / "proofs.db")
    offline = reg.issue("tenant_1", "example.com", now=NOW)
    v1 = reg.confirm("tenant_1", offline.id,
                     lambda _: [offline.record_value], now=NOW + 1)
    with pytest.raises(ProofError):
        reg.require_dns_verified("tenant_1", v1.id, now=NOW + 2)
    challenge = reg.issue("tenant_1", "example.com", now=NOW)
    v2 = reg.confirm(
        "tenant_1", challenge.id, lambda _: [challenge.record_value],
        now=NOW + 1, verification_method="doh-quorum",
    )
    reg.require_dns_verified("tenant_1", v2.id, now=NOW + 2)
