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
