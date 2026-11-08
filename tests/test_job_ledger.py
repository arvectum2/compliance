"""Internal-only job accounting. DNS confirmations here are explicit mocks."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.domain_proof import ProofError
from arvectum_compliance.service.job_ledger import JobLedger
from arvectum_compliance.service.sqlite_proof import SqliteOwnershipRegistry

NOW = 1800000000
SIGN_KEY = b"Z" * 32


def provision(tmp_path, *, tenant="org_A"):
    proofs = SqliteOwnershipRegistry(tmp_path / "proofs.db")
    pending = proofs.issue(tenant, "example.com", now=NOW)
    # Simulates a trusted resolver, never used as real DNS evidence in production.
    proof = proofs.confirm(
        tenant, pending.id, lambda _: [pending.record_value],
        verification_method="doh-quorum", now=NOW + 1,
    )
    issuer = GrantIssuer(proofs, SIGN_KEY)
    ledger = JobLedger(tmp_path / "jobs.db")
    return proofs, proof, issuer, ledger


def new_grant(issuer, proof, job="job_1"):
    return issuer.issue(proof, job, policy_version="gateway-v2", now=NOW + 2)


def test_verified_job_success_has_only_anonymized_status(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    grant = new_grant(issuer, proof)
    ledger.enqueue(grant, issuer=issuer, proofs=proofs, now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    assert claim.hostname == "example.com"
    assert claim.proof == proof.id
    assert claim.token
    ledger.finish(
        claim, worker="worker_1", state="completed", proofs=proofs,
        bytes_count=123, sha256="a" * 64, now=NOW + 5,
    )
    assert ledger.status("org_A", "job_1") == ("completed", 123, "a" * 64)
    assert [state for _, state in ledger.events("org_A", "job_1")] == [
        "queued", "running", "completed",
    ]
    db_bytes = ledger.path.read_bytes()
    assert claim.token.encode() not in db_bytes
    assert grant.signature.encode() not in db_bytes
    assert b"SECRET_CANARY" not in db_bytes
    assert os.stat(ledger.path).st_mode & 0o777 == 0o600


def test_no_fake_dns_or_tampered_grant_may_be_queued(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    challenge = proofs.issue("org_A", "another.example", now=NOW)
    mocked = proofs.confirm(
        "org_A", challenge.id, lambda _: [challenge.record_value], now=NOW + 1,
    )
    with pytest.raises(ProofError, match="Real DNS"):
        ledger.enqueue(
            new_grant(issuer, mocked, "job_fake"),
            issuer=issuer, proofs=proofs, now=NOW + 3,
        )
    grant = new_grant(issuer, proof)
    with pytest.raises(ProofError):
        ledger.enqueue(
            replace(grant, signature="0" * 64),
            issuer=issuer, proofs=proofs, now=NOW + 3,
        )
    assert ledger.claim("worker_1", proofs=proofs, now=NOW + 4) is None


def test_idempotent_enqueue_and_no_id_reuse(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    grant = new_grant(issuer, proof)
    for _ in range(2):
        ledger.enqueue(grant, issuer=issuer, proofs=proofs, now=NOW + 3)
    assert ledger.events("org_A", "job_1") == [(NOW + 3, "queued")]
    with pytest.raises(ProofError, match="different signed grant"):
        ledger.enqueue(
            new_grant(issuer, proof), issuer=issuer, proofs=proofs,
            now=NOW + 3,
        )


def test_atomic_claim_only_one_worker_wins(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    def take(number):
        return JobLedger(ledger.path).claim(
            f"worker_{number}", proofs=proofs, now=NOW + 4,
        )
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(take, range(12)))
    assert len([claim for claim in claims if claim is not None]) == 1
    assert len(ledger.events("org_A", "job_1")) == 2


def test_lease_expiry_fails_closed_and_is_not_retried(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    with pytest.raises(ProofError, match="Expired"):
        ledger.finish(
            claim, worker="worker_1", state="completed", proofs=proofs,
            bytes_count=10, sha256="a" * 64, now=NOW + 34,
        )
    assert ledger.status("org_A", "job_1")[0] == "expired"
    assert ledger.claim("worker_2", proofs=proofs, now=NOW + 35) is None


def test_revocation_while_queued_cancels_before_claim(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    proofs.revoke("org_A", proof.id)
    assert ledger.claim("worker_1", proofs=proofs, now=NOW + 4) is None
    assert ledger.status("org_A", "job_1")[0] == "denied"


def test_revocation_while_running_blocks_completed_result(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    proofs.revoke("org_A", proof.id)
    with pytest.raises(ProofError, match="Real DNS"):
        ledger.finish(
            claim, worker="worker_1", state="completed", proofs=proofs,
            bytes_count=10, sha256="a" * 64, now=NOW + 5,
        )
    assert ledger.status("org_A", "job_1")[0] == "denied"


def test_wrong_worker_or_token_never_completes(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    for suspect, worker in [(claim, "worker_2"),
                            (replace(claim, token="CANARY"), "worker_1")]:
        with pytest.raises(ProofError):
            ledger.finish(
                suspect, worker=worker, state="completed", proofs=proofs,
                bytes_count=10, sha256="a" * 64, now=NOW + 5,
            )
    ledger.finish(claim, worker="worker_1", state="denied",
                  proofs=proofs, now=NOW + 6)
    with pytest.raises(ProofError):
        ledger.finish(claim, worker="worker_1", state="denied",
                      proofs=proofs, now=NOW + 7)


def test_tenant_status_isolation_and_reopening(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    with pytest.raises(ProofError, match="unavailable"):
        ledger.status("other_tenant", "job_1")
    with pytest.raises(ProofError):
        ledger.events("other_tenant", "job_1")
    again = JobLedger(ledger.path)
    assert again.status("org_A", "job_1")[0] == "queued"


def test_retention_deletes_terminal_events_without_touching_new_jobs(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    ledger.finish(claim, worker="worker_1", state="denied", proofs=proofs,
                  now=NOW + 5)
    assert ledger.prune(now=NOW + 86399, days=1) == 0
    assert ledger.prune(now=NOW + 86406, days=1) == 1
    with pytest.raises(ProofError):
        ledger.status("org_A", "job_1")
    with ledger._db() as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_invalid_retention_and_summary_never_stored(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    with pytest.raises(ValueError):
        ledger.prune(days=0)
    with pytest.raises(ValueError):
        ledger.prune(limit=0)
    with pytest.raises(ValueError):
        ledger.finish(
            claim, worker="worker_1", state="completed", proofs=proofs,
            bytes_count=100, sha256="SECRET_CANARY", now=NOW + 5,
        )
    with pytest.raises(ValueError):
        ledger.finish(
            claim, worker="worker_1", state="failed", proofs=proofs,
            sha256="a" * 64, now=NOW + 5,
        )
    assert ledger.status("org_A", "job_1")[0] == "running"
    assert b"SECRET_CANARY" not in ledger.path.read_bytes()


def test_expired_signed_grant_is_not_enqueued(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    grant = new_grant(issuer, proof)
    with pytest.raises(ProofError):
        ledger.enqueue(grant, issuer=issuer, proofs=proofs,
                       now=grant.expires_at + 1)
    assert ledger.claim("worker_1", proofs=proofs, now=NOW + 4) is None


def test_unsafe_database_file_and_symlink_refused(tmp_path):
    path = tmp_path / "jobs.db"
    JobLedger(path)
    os.chmod(path, 0o644)
    with pytest.raises(ProofError):
        JobLedger(path)
    os.chmod(path, 0o600)
    link = tmp_path / "alias.db"
    link.symlink_to(path)
    with pytest.raises(ProofError):
        JobLedger(link)


def test_queue_limit_enforced_per_tenant(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for index in range(100):
        ledger.enqueue(
            new_grant(issuer, proof, f"job_{index}"),
            issuer=issuer, proofs=proofs, now=NOW + 3,
        )
    with pytest.raises(ProofError, match="full"):
        ledger.enqueue(new_grant(issuer, proof, "job_overflow"),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    assert ledger.status("org_A", "job_0")[0] == "queued"


def test_claim_proof_substitution_cannot_bypass_revocation(tmp_path):
    """A worker can edit Claim fields, but cannot rewrite durable ownership."""
    proofs, proof, issuer, ledger = provision(tmp_path)
    other_pending = proofs.issue("org_A", "second.example.com", now=NOW)
    other = proofs.confirm(
        "org_A", other_pending.id, lambda _: [other_pending.record_value],
        verification_method="doh-quorum", now=NOW + 1,
    )
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    proofs.revoke("org_A", proof.id)
    for altered in (
        replace(claim, proof=other.id),
        replace(claim, hostname="second.example.com", proof=other.id),
    ):
        with pytest.raises(ProofError, match="does not match"):
            ledger.finish(
                altered, worker="worker_1", state="completed",
                proofs=proofs, bytes_count=4, sha256="b" * 64, now=NOW + 5,
            )
    assert ledger.status("org_A", "job_1")[0] == "running"
    with pytest.raises(ProofError, match="Real DNS"):
        ledger.finish(
            claim, worker="worker_1", state="completed", proofs=proofs,
            bytes_count=4, sha256="b" * 64, now=NOW + 5,
        )
    assert ledger.status("org_A", "job_1")[0] == "denied"


def test_reconcile_revocation_cancels_active_lease(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    proofs.revoke("org_A", proof.id)
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 5) == 1
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 6) == 0
    assert ledger.status("org_A", "job_1") == ("denied", None, None)
    with pytest.raises(ProofError):
        ledger.finish(
            claim, worker="worker_1", state="completed", proofs=proofs,
            bytes_count=1, sha256="a" * 64, now=NOW + 7,
        )
    assert [state for _, state in ledger.events("org_A", "job_1")] == [
        "queued", "running", "denied",
    ]


def test_reconcile_revocation_cancels_queued_job(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    proofs.revoke("org_A", proof.id)
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 4) == 1
    assert ledger.claim("worker_1", proofs=proofs, now=NOW + 5) is None
    assert ledger.status("org_A", "job_1")[0] == "denied"


def test_reconcile_retains_healthy_jobs_and_bounds_batch(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for index in range(3):
        ledger.enqueue(
            new_grant(issuer, proof, f"job_{index}"),
            issuer=issuer, proofs=proofs, now=NOW + 3,
        )
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 4) == 0
    with pytest.raises(ValueError):
        ledger.reconcile_revocations(proofs=proofs, now=NOW + 4, limit=0)
    with pytest.raises(ValueError):
        ledger.reconcile_revocations(proofs=proofs, now=NOW + 4, limit=True)
    proofs.revoke("org_A", proof.id)
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 5, limit=2) == 2
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 6, limit=2) == 1
    assert all(
        ledger.status("org_A", f"job_{i}")[0] == "denied" for i in range(3)
    )


def test_reconciliation_cursor_advances_past_healthy_prefix(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for i in range(5):
        ledger.enqueue(new_grant(issuer, proof, f"healthy_{i}"),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    other = proofs.issue("org_A", "other.example.com", now=NOW)
    revoked = proofs.confirm(
        "org_A", other.id, lambda _: [other.record_value],
        verification_method="doh-quorum", now=NOW + 1,
    )
    ledger.enqueue(new_grant(issuer, revoked, "revoked_job"),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    proofs.revoke("org_A", revoked.id)
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 4, limit=2) == 0
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 4, limit=2) == 0
    # Cursor survives process restart and reaches the tail.
    reopened = JobLedger(ledger.path)
    assert reopened.reconcile_revocations(
        proofs=proofs, now=NOW + 4, limit=2,
    ) == 1
    assert reopened.status("org_A", "revoked_job")[0] == "denied"
    assert reopened.reconcile_revocations(
        proofs=proofs, now=NOW + 4, limit=2,
    ) == 0
    assert all(reopened.status("org_A", f"healthy_{i}")[0] == "queued"
               for i in range(5))


def test_reconciliation_cursor_wraps_after_deleted_tail(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for i in range(3):
        ledger.enqueue(new_grant(issuer, proof, f"job_{i}"),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 4, limit=2) == 0
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 4, limit=2) == 0
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 4, limit=2) == 0
    proofs.revoke("org_A", proof.id)
    # Every active job is reached across bounded sweeps despite cursor wrap.
    for _ in range(3):
        ledger.reconcile_revocations(proofs=proofs, now=NOW + 5, limit=1)
    assert all(ledger.status("org_A", f"job_{i}")[0] == "denied"
               for i in range(3))


def test_claim_denies_durable_hostname_proof_mismatch(tmp_path):
    """A valid proof for another host must not authorize a corrupted job."""
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    with ledger._db() as db:
        db.execute(
            "UPDATE jobs SET hostname=? WHERE tenant=? AND job=?",
            ("different.example.com", "org_A", "job_1"),
        )
    assert ledger.claim("worker_1", proofs=proofs, now=NOW + 4) is None
    assert ledger.status("org_A", "job_1")[0] == "denied"


def test_finish_denies_corrupted_durable_hostname_even_with_matching_claim(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    with ledger._db() as db:
        db.execute(
            "UPDATE jobs SET hostname=? WHERE tenant=? AND job=?",
            ("different.example.com", "org_A", "job_1"),
        )
    with pytest.raises(ProofError, match="Real DNS"):
        ledger.finish(
            replace(claim, hostname="different.example.com"),
            worker="worker_1", state="completed", proofs=proofs,
            bytes_count=1, sha256="a" * 64, now=NOW + 5,
        )
    assert ledger.status("org_A", "job_1") == ("denied", None, None)


def test_reconcile_denies_corrupted_hostname_without_releasing_lease(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof),
                   issuer=issuer, proofs=proofs, now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    with ledger._db() as db:
        db.execute(
            "UPDATE jobs SET hostname=? WHERE tenant=? AND job=?",
            ("different.example.com", "org_A", "job_1"),
        )
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 5) == 1
    assert ledger.status("org_A", "job_1")[0] == "denied"
    with pytest.raises(ProofError):
        ledger.finish(claim, worker="worker_1", state="denied",
                      proofs=proofs, now=NOW + 6)


def test_enqueue_rejects_signed_grant_with_mismatched_durable_host(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    grant = new_grant(issuer, proof)
    with proofs._connect() as db:
        db.execute(
            "UPDATE domain_proofs SET hostname=? WHERE id=?",
            ("other.example", proof.id),
        )
    with pytest.raises(ProofError):
        ledger.enqueue(grant, issuer=issuer, proofs=proofs, now=NOW + 3)
    with pytest.raises(ProofError):
        ledger.status("org_A", "job_1")


def test_single_snapshot_proof_method_and_revocation_gate(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    proofs.require_dns_verified_host(
        "org_A", proof.id, "example.com", now=NOW + 3,
    )
    with pytest.raises(ProofError):
        proofs.require_dns_verified_host(
            "other_tenant", proof.id, "example.com", now=NOW + 3,
        )
    with pytest.raises(ProofError):
        proofs.require_dns_verified_host(
            "org_A", proof.id, "other.example", now=NOW + 3,
        )
    with proofs._connect() as db:
        db.execute(
            "UPDATE domain_proofs SET verified_method='offline-test' WHERE id=?",
            (proof.id,),
        )
    with pytest.raises(ProofError):
        ledger.enqueue(new_grant(issuer, proof),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    with proofs._connect() as db:
        db.execute(
            "UPDATE domain_proofs SET verified_method='doh-quorum' WHERE id=?",
            (proof.id,),
        )
    proofs.revoke("org_A", proof.id)
    with pytest.raises(ProofError):
        proofs.require_dns_verified_host(
            "org_A", proof.id, "example.com", now=NOW + 4,
        )


def test_expiry_sweep_is_bounded_and_repeatable(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for index in range(9):
        ledger.enqueue(
            new_grant(issuer, proof, f"batch_{index}"),
            issuer=issuer, proofs=proofs, now=NOW + 3,
        )
    assert ledger.expire_batch(now=NOW + 5000, limit=3) == 3
    assert ledger.expire_batch(now=NOW + 5000, limit=3) == 3
    assert ledger.expire_batch(now=NOW + 5000, limit=3) == 3
    assert ledger.expire_batch(now=NOW + 5000, limit=3) == 0
    assert all(ledger.status("org_A", f"batch_{i}")[0] == "expired"
               for i in range(9))
    assert all(len(ledger.events("org_A", f"batch_{i}")) == 2
               for i in range(9))
    with pytest.raises(ValueError):
        ledger.expire_batch(limit=0)


def test_stale_unmaterialized_jobs_do_not_consume_active_tenant_quota(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for index in range(100):
        ledger.enqueue(
            new_grant(issuer, proof, f"stale_{index}"),
            issuer=issuer, proofs=proofs, now=NOW + 3,
        )
    # Simulate the old entries remaining in SQLite after bounded maintenance.
    with ledger._db() as db:
        db.execute(
            "UPDATE jobs SET expires=? WHERE tenant='org_A'",
            (NOW + 4,),
        )
    ledger.enqueue(
        new_grant(issuer, proof, "new_after_stale"),
        issuer=issuer, proofs=proofs, now=NOW + 5,
    )
    assert ledger.status("org_A", "new_after_stale")[0] == "queued"


def test_expired_running_job_never_reconciled_as_active(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(
        new_grant(issuer, proof), issuer=issuer, proofs=proofs, now=NOW + 3,
    )
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    assert claim is not None
    with ledger._db() as db:
        db.execute(
            "UPDATE jobs SET lease_expires=? WHERE tenant=? AND job=?",
            (NOW + 4, claim.tenant, claim.job),
        )
    assert ledger.reconcile_revocations(proofs=proofs, now=NOW + 5) == 0
    assert ledger.status("org_A", "job_1")[0] == "expired"


def test_claim_revoked_fifo_prefix_is_bounded_and_resumable(tmp_path):
    proofs, revoked_proof, issuer, ledger = provision(tmp_path)
    for i in range(8):
        ledger.enqueue(
            new_grant(issuer, revoked_proof, f"revoked_{i:02}"),
            issuer=issuer, proofs=proofs, now=NOW + 3,
        )
    pending = proofs.issue("org_A", "healthy.example.com", now=NOW)
    healthy_proof = proofs.confirm(
        "org_A", pending.id, lambda _: [pending.record_value],
        verification_method="doh-quorum", now=NOW + 1,
    )
    ledger.enqueue(
        new_grant(issuer, healthy_proof, "z_healthy"),
        issuer=issuer, proofs=proofs, now=NOW + 3,
    )
    proofs.revoke("org_A", revoked_proof.id)
    with pytest.raises(ValueError):
        ledger.claim("worker_1", proofs=proofs, now=NOW + 4,
                     rejection_limit=0)
    assert ledger.claim("worker_1", proofs=proofs, now=NOW + 4,
                        rejection_limit=3) is None
    assert [ledger.status("org_A", f"revoked_{i:02}")[0]
            for i in range(8)] == ["denied"] * 3 + ["queued"] * 5
    assert ledger.claim("worker_1", proofs=proofs, now=NOW + 5,
                        rejection_limit=3) is None
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 6,
                         rejection_limit=3)
    assert claim is not None and claim.job == "z_healthy"
    assert all(ledger.status("org_A", f"revoked_{i:02}")[0] == "denied"
               for i in range(8))
    assert all(len(ledger.events("org_A", f"revoked_{i:02}")) == 2
               for i in range(8))


def test_expiry_and_retention_indexes_survive_reopening(tmp_path):
    """Bounded maintenance must not require a full-table scan on each tick."""
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(
        new_grant(issuer, proof), issuer=issuer, proofs=proofs, now=NOW + 3,
    )
    reopened = JobLedger(ledger.path)
    with reopened._db() as db:
        indexes = {
            row[1] for row in db.execute("PRAGMA index_list('jobs')")
        }
        assert {
            "jobs_expiry_idx", "jobs_lease_expiry_idx",
            "jobs_tenant_active_idx", "jobs_terminal_retention_idx",
        } <= indexes
        queued_plan = " ".join(
            str(row) for row in db.execute(
                "EXPLAIN QUERY PLAN SELECT tenant,job FROM jobs "
                "WHERE state='queued' AND expires<=?", (NOW + 4,),
            )
        )
        running_plan = " ".join(
            str(row) for row in db.execute(
                "EXPLAIN QUERY PLAN SELECT tenant,job FROM jobs "
                "WHERE state='running' AND lease_expires<=?", (NOW + 4,),
            )
        )
        assert "jobs_expiry_idx" in queued_plan
        assert "jobs_lease_expiry_idx" in running_plan
    assert reopened.status("org_A", "job_1")[0] == "queued"


def test_read_only_integrity_audit_detects_corrupt_worker_lease(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    assert claim is not None
    assert ledger.audit_integrity() == {
        "checked": 1, "total": 1, "anomalies": 0, "complete": 1,
    }
    before = ledger.events("org_A", "job_1")
    with ledger._db() as db:
        db.execute(
            "UPDATE jobs SET lease_digest=NULL WHERE tenant=? AND job=?",
            (claim.tenant, claim.job),
        )
    assert ledger.audit_integrity()["anomalies"] == 1
    assert ledger.events("org_A", "job_1") == before


def test_integrity_audit_rejects_terminal_metadata_and_bounded_scan(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for i in range(3):
        ledger.enqueue(new_grant(issuer, proof, f"job_{i}"),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    assert ledger.audit_integrity(limit=2) == {
        "checked": 2, "total": 3, "anomalies": 0, "complete": 0,
    }
    with pytest.raises(ValueError):
        ledger.audit_integrity(limit=0)
    with ledger._db() as db:
        db.execute(
            "UPDATE jobs SET state='completed',sha256='INVALID',"
            "bytes_count=12 WHERE job='job_0'",
        )
    assert ledger.audit_integrity(limit=2)["anomalies"] == 1


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("tenant", "bad/tenant"),
        ("job", "bad/job"),
        ("hostname", "https://example.com"),
        ("hostname", "EXAMPLE.COM"),
        ("proof", "bad/proof"),
        ("grant_digest", "not-a-digest"),
        ("worker", "stale_worker"),
        ("expires", NOW + 2),
    ],
)
def test_integrity_audit_rejects_corrupt_queued_identity_and_metadata(
    tmp_path, column, value,
):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer,
                   proofs=proofs, now=NOW + 3)
    assert ledger.audit_integrity()["anomalies"] == 0
    with ledger._db() as db:
        # Simulate offline tampering; normal SQLite FK enforcement forbids
        # changes to primary keys referenced by the event journal.
        if column in ("tenant", "job"):
            db.execute("PRAGMA foreign_keys=OFF")
        db.execute(
            f"UPDATE jobs SET {column}=? WHERE tenant='org_A' AND job='job_1'",
            (value,),
        )
    # A modified primary key also strands the old event journal row.
    expected = 3 if column in ("tenant", "job") else 1
    assert ledger.audit_integrity()["anomalies"] == expected


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("worker", "bad/worker"),
        ("lease_expires", NOW + 3),
        ("lease_expires", NOW + 5000),
    ],
)
def test_integrity_audit_rejects_corrupt_running_worker_and_lease(
    tmp_path, column, value,
):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer,
                   proofs=proofs, now=NOW + 3)
    ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    assert ledger.audit_integrity()["anomalies"] == 0
    with ledger._db() as db:
        db.execute(
            f"UPDATE jobs SET {column}=? WHERE tenant='org_A' AND job='job_1'",
            (value,),
        )
    assert ledger.audit_integrity()["anomalies"] == 1


@pytest.mark.parametrize("corruption", ["missing", "wrong_state", "wrong_moment"])
def test_integrity_audit_detects_event_journal_divergence(tmp_path, corruption):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer,
                   proofs=proofs, now=NOW + 3)
    assert ledger.audit_integrity()["anomalies"] == 0
    with ledger._db() as db:
        if corruption == "missing":
            db.execute("DELETE FROM events WHERE tenant='org_A' AND job='job_1'")
        elif corruption == "wrong_state":
            db.execute("UPDATE events SET state='running' "
                       "WHERE tenant='org_A' AND job='job_1'")
        else:
            db.execute("UPDATE events SET moment=moment+1 "
                       "WHERE tenant='org_A' AND job='job_1'")
    expected = 2
    assert ledger.audit_integrity()["anomalies"] == expected


def test_integrity_audit_detects_orphaned_journal_outside_job_scan(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer,
                   proofs=proofs, now=NOW + 3)
    with ledger._db() as db:
        db.execute("PRAGMA foreign_keys=OFF")
        db.execute("INSERT INTO events VALUES (?,?,?,?)",
                   ("org_orphan", "job_orphan", NOW + 3, "queued"))
    assert ledger.audit_integrity() == {
        "checked": 1, "total": 1, "anomalies": 1, "complete": 1,
    }
    assert ledger.audit_integrity(limit=1)["anomalies"] == 1


@pytest.mark.parametrize("corruption", ["state", "early", "future", "type"])
def test_integrity_audit_detects_historical_event_corruption_outside_scan(
    tmp_path, corruption,
):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer,
                   proofs=proofs, now=NOW + 3)
    with ledger._db() as db:
        # Insert a historical event that is not the latest event for the job.
        db.execute("INSERT INTO events VALUES (?,?,?,?)",
                   ("org_A", "job_1", NOW + 3, "queued"))
        rowid = db.execute("SELECT max(rowid) FROM events").fetchone()[0]
        if corruption == "state":
            db.execute("UPDATE events SET state='invalid' WHERE rowid=?", (rowid,))
        elif corruption == "early":
            db.execute("UPDATE events SET moment=? WHERE rowid=?", (NOW, rowid))
        elif corruption == "future":
            db.execute("UPDATE events SET moment=? WHERE rowid=?", (NOW + 100, rowid))
        else:
            db.execute("UPDATE events SET moment='invalid' WHERE rowid=?", (rowid,))
    assert ledger.audit_integrity(limit=1)["anomalies"] >= 1


@pytest.mark.parametrize("corruption", ["backwards", "first_state"])
def test_integrity_audit_rejects_invalid_journal_order(tmp_path, corruption):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer,
                   proofs=proofs, now=NOW + 3)
    claim = ledger.claim("worker_1", proofs=proofs, now=NOW + 4)
    assert claim is not None
    assert ledger.audit_integrity()["anomalies"] == 0
    with ledger._db() as db:
        if corruption == "backwards":
            # Both moments remain within the job lifetime; only ordering
            # reveals the forged chronology.
            db.execute(
                "UPDATE events SET moment=? WHERE state='queued'",
                (NOW + 4,),
            )
            db.execute(
                "UPDATE events SET moment=? WHERE state='running'",
                (NOW + 3,),
            )
        else:
            db.execute(
                "UPDATE events SET state='running' WHERE state='queued'"
            )
    assert ledger.audit_integrity()["anomalies"] >= 1


@pytest.mark.parametrize("states", [
    ("queued", "completed"),
    ("queued", "failed"),
    ("queued", "queued"),
    ("queued", "running", "running"),
    ("queued", "denied", "running"),
    ("queued", "running", "completed", "expired"),
])
def test_integrity_audit_rejects_illegal_state_transitions(tmp_path, states):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer,
                   proofs=proofs, now=NOW + 3)
    with ledger._db() as db:
        db.execute("DELETE FROM events")
        for state in states:
            db.execute("INSERT INTO events VALUES (?,?,?,?)",
                       ("org_A", "job_1", NOW + 3, state))
        db.execute("UPDATE jobs SET state=? WHERE tenant=? AND job=?",
                   (states[-1], "org_A", "job_1"))
    assert ledger.audit_integrity()["anomalies"] >= 1



def test_integrity_audit_detects_missing_history_outside_bounded_scan(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for index in range(3):
        ledger.enqueue(new_grant(issuer, proof, f"job_{index}"),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    assert ledger.audit_integrity(limit=1)["anomalies"] == 0
    with ledger._db() as db:
        db.execute("DELETE FROM events WHERE tenant=? AND job=?",
                   ("org_A", "job_2"))
    result = ledger.audit_integrity(limit=1)
    assert result == {"checked": 1, "total": 3, "anomalies": 1, "complete": 0}
    assert ledger.events("org_A", "job_2") == []


def test_integrity_audit_detects_stale_latest_event_outside_bounded_scan(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for index in range(3):
        ledger.enqueue(new_grant(issuer, proof, f"job_{index}"),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    assert ledger.audit_integrity(limit=1)["anomalies"] == 0
    with ledger._db() as db:
        db.execute("UPDATE jobs SET updated=updated+1 WHERE tenant=? AND job=?",
                   ("org_A", "job_2"))
    result = ledger.audit_integrity(limit=1)
    assert result["anomalies"] >= 1
    assert result["complete"] == 0


def test_integrity_audit_detects_bad_grant_digest_outside_bounded_scan(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for index in range(3):
        ledger.enqueue(new_grant(issuer, proof, f"job_{index}"),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    assert ledger.audit_integrity(limit=1)["anomalies"] == 0
    with ledger._db() as db:
        db.execute("UPDATE jobs SET grant_digest=? WHERE tenant=? AND job=?",
                   ("X" * 64, "org_A", "job_2"))
    assert ledger.audit_integrity(limit=1) == {
        "checked": 1, "total": 3, "anomalies": 1, "complete": 0,
    }


def test_integrity_audit_detects_noncanonical_host_outside_sample(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for index in range(3):
        ledger.enqueue(new_grant(issuer, proof, f"job_{index}"),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    assert ledger.audit_integrity(limit=1)["anomalies"] == 0
    with ledger._db() as db:
        db.execute("UPDATE jobs SET hostname=? WHERE tenant=? AND job=?",
                   ("EXAMPLE.COM", "org_A", "job_2"))
    assert ledger.audit_integrity(limit=1) == {
        "checked": 1, "total": 3, "anomalies": 1, "complete": 0,
    }


@pytest.mark.parametrize("field,value", [
    ("worker", "bad worker"),
    ("lease_digest", "not-a-digest"),
    ("lease_expires", NOW + 100000),
    ("bytes_count", 12),
    ("created", "invalid"),
])
def test_integrity_audit_detects_tail_lease_metadata(tmp_path, field, value):
    proofs, proof, issuer, ledger = provision(tmp_path)
    for index in range(3):
        ledger.enqueue(new_grant(issuer, proof, f"job_{index}"),
                       issuer=issuer, proofs=proofs, now=NOW + 3)
    assert ledger.audit_integrity(limit=1)["anomalies"] == 0
    with ledger._db() as db:
        db.execute(f"UPDATE jobs SET {field}=? WHERE tenant=? AND job=?",
                   (value, "org_A", "job_2"))
    assert ledger.audit_integrity(limit=1)["anomalies"] >= 1


@pytest.mark.parametrize(("field", "value"), [
    ("name", "unexpected"),
    ("created", -1),
    ("created", "invalid"),
    ("tenant", "bad/tenant"),
    ("job", "bad/job"),
])
def test_integrity_audit_rejects_corrupt_reconciliation_cursor(
    tmp_path, field, value,
):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    with ledger._db() as db:
        db.execute(
            "INSERT INTO maintenance_cursor(name,created,tenant,job) "
            "VALUES ('revocations',?,?,?)", (NOW + 3, "org_A", "job_1"),
        )
    assert ledger.audit_integrity()["anomalies"] == 0
    with ledger._db() as db:
        db.execute(f"UPDATE maintenance_cursor SET {field}=?", (value,))
    assert ledger.audit_integrity()["anomalies"] >= 1


def test_integrity_audit_uses_single_read_snapshot(tmp_path, monkeypatch):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    statements = []
    original_db = ledger._db

    def traced_db(*, readonly=False):
        assert readonly is True
        db = original_db(readonly=readonly)
        db.set_trace_callback(statements.append)
        return db

    monkeypatch.setattr(ledger, "_db", traced_db)
    assert ledger.audit_integrity()["anomalies"] == 0
    sql = [statement.strip().upper() for statement in statements]
    assert "BEGIN" in sql
    assert sql.index("BEGIN") < next(
        i for i, statement in enumerate(sql) if statement.startswith("SELECT")
    )
    assert not any(statement.startswith(("INSERT", "UPDATE", "DELETE"))
                   for statement in sql)


def test_integrity_audit_rejects_shifted_enqueue_event(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer,
                   proofs=proofs, now=NOW + 3)
    assert ledger.audit_integrity()["anomalies"] == 0
    with ledger._db() as db:
        db.execute(
            "UPDATE events SET moment=moment+1 WHERE state='queued' "
            "AND tenant='org_A' AND job='job_1'"
        )
    # The timestamp remains inside the job's lifetime only if updated
    # also advances; neither change may forge the original enqueue time.
    with ledger._db() as db:
        db.execute(
            "UPDATE jobs SET updated=updated+1 WHERE tenant='org_A' "
            "AND job='job_1'"
        )
    assert ledger.audit_integrity()["anomalies"] >= 1


def test_integrity_audit_connection_rejects_writes(tmp_path):
    import sqlite3

    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    with ledger._db(readonly=True) as db:
        assert db.execute("PRAGMA query_only").fetchone()[0] == 1
        assert db.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        with pytest.raises(sqlite3.OperationalError):
            db.execute("DELETE FROM jobs")
    assert ledger.audit_integrity()["anomalies"] == 0


def test_integrity_audit_checks_declared_foreign_keys(tmp_path):
    # A valid SQLite file may contain broken foreign keys even when
    # PRAGMA quick_check returns ok. The diagnostic must reject them.
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    with ledger._db() as db:
        db.execute("PRAGMA foreign_keys=OFF")
        db.execute("INSERT INTO events VALUES (?,?,?,?)",
                   ("orphan_tenant", "orphan_job", NOW + 3, "queued"))
    assert ledger.audit_integrity()["anomalies"] >= 1


def test_integrity_audit_checks_full_sqlite_integrity(tmp_path, monkeypatch):
    # Unlike quick_check, integrity_check validates index consistency too.
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    original = ledger._db
    statements = []

    def traced_db(*, readonly=False):
        db = original(readonly=readonly)
        if readonly:
            db.set_trace_callback(statements.append)
        return db

    monkeypatch.setattr(ledger, "_db", traced_db)
    assert ledger.audit_integrity()["anomalies"] == 0
    assert any("PRAGMA integrity_check(1)" in sql for sql in statements)
    assert not any("PRAGMA quick_check" in sql for sql in statements)


def test_integrity_audit_clean_foreign_keys(tmp_path):
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    assert ledger.audit_integrity()["anomalies"] == 0


def test_integrity_audit_rejects_missing_maintenance_index(tmp_path):
    # SQLite integrity_check still returns ok after a legitimate DROP INDEX,
    # but the ledger must not start workers with degraded maintenance indexes.
    proofs, proof, issuer, ledger = provision(tmp_path)
    ledger.enqueue(new_grant(issuer, proof), issuer=issuer, proofs=proofs,
                   now=NOW + 3)
    with ledger._db() as db:
        db.execute("DROP INDEX jobs_lease_expiry_idx")
        assert db.execute("PRAGMA integrity_check(1)").fetchone()[0] == "ok"
    assert ledger.audit_integrity()["anomalies"] >= 1
