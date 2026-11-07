"""Offline-only private job queue; no HTML, full URLs or bearer tokens stored."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .authorization import GrantIssuer, ScanGrant
from .domain_proof import ProofError, _identifier
from .sqlite_proof import SqliteOwnershipRegistry


@dataclass(frozen=True)
class Claim:
    tenant: str
    job: str
    hostname: str
    proof: str
    token: str


class JobLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.is_symlink() or not self.path.parent.is_dir():
            raise ProofError("Unsafe job database")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        mode = self.path.stat().st_mode
        if not stat.S_ISREG(mode) or mode & 0o777 != 0o600:
            raise ProofError("Job store must be private regular file")
        with self._db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs(
              tenant TEXT NOT NULL, job TEXT NOT NULL, hostname TEXT NOT NULL,
              proof TEXT NOT NULL, grant_digest TEXT NOT NULL,
              expires INTEGER NOT NULL, state TEXT NOT NULL,
              created INTEGER NOT NULL, updated INTEGER NOT NULL,
              worker TEXT, lease_digest TEXT, lease_expires INTEGER,
              bytes_count INTEGER, sha256 TEXT,
              PRIMARY KEY(tenant,job));
            CREATE TABLE IF NOT EXISTS events(
              tenant TEXT NOT NULL, job TEXT NOT NULL, moment INTEGER NOT NULL,
              state TEXT NOT NULL,
              FOREIGN KEY(tenant,job) REFERENCES jobs(tenant,job) ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS jobs_queue_idx ON jobs(state,created);
            CREATE TABLE IF NOT EXISTS maintenance_cursor(
              name TEXT PRIMARY KEY, created INTEGER NOT NULL,
              tenant TEXT NOT NULL, job TEXT NOT NULL);
            """)

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _expire(db: sqlite3.Connection, t: int) -> None:
        expired = db.execute(
            "SELECT tenant,job FROM jobs WHERE "
            "(state='queued' AND expires<=?) OR "
            "(state='running' AND (lease_expires<=? OR expires<=?))",
            (t, t, t),
        ).fetchall()
        for tenant, job in expired:
            db.execute(
                "UPDATE jobs SET state='expired',updated=?,lease_digest=NULL,"
                "lease_expires=NULL WHERE tenant=? AND job=?", (t, tenant, job),
            )
            db.execute(
                "INSERT INTO events VALUES (?,?,?,?)", (tenant, job, t, "expired"),
            )

    def enqueue(
        self, grant: ScanGrant, *, issuer: GrantIssuer,
        proofs: SqliteOwnershipRegistry, now: int | None = None,
    ) -> None:
        t = int(time.time()) if now is None else int(now)
        if grant.policy_version != "gateway-v2":
            raise ProofError("Signed gateway-v2 grant required")
        issuer.require_active(
            grant, tenant_id=grant.tenant_id, job_id=grant.job_id, now=t,
        )
        proofs.require_dns_verified(grant.tenant_id, grant.proof_id, now=t)
        digest = hashlib.sha256(grant.signature.encode("ascii")).hexdigest()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire(db, t)
            prior = db.execute(
                "SELECT grant_digest FROM jobs WHERE tenant=? AND job=?",
                (grant.tenant_id, grant.job_id),
            ).fetchone()
            if prior:
                if prior[0] != digest:
                    raise ProofError("Job ID used with different signed grant")
            else:
                count = db.execute(
                    "SELECT count(*) FROM jobs WHERE tenant=? "
                    "AND state IN ('queued','running')",
                    (grant.tenant_id,),
                ).fetchone()[0]
                if count >= 100:
                    raise ProofError("Tenant job queue full")
                db.execute(
                    "INSERT INTO jobs(tenant,job,hostname,proof,grant_digest,"
                    "expires,state,created,updated) VALUES (?,?,?,?,?,?,?,?,?)",
                    (grant.tenant_id, grant.job_id, grant.hostname, grant.proof_id,
                     digest, grant.expires_at, "queued", t, t),
                )
                db.execute(
                    "INSERT INTO events VALUES (?,?,?,?)",
                    (grant.tenant_id, grant.job_id, t, "queued"),
                )
            db.execute("COMMIT")

    def claim(
        self, worker: str, *, proofs: SqliteOwnershipRegistry,
        now: int | None = None,
    ) -> Claim | None:
        worker = _identifier(worker)
        t = int(time.time()) if now is None else int(now)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire(db, t)
            while True:
                row = db.execute(
                    "SELECT tenant,job,hostname,proof,expires FROM jobs "
                    "WHERE state='queued' AND expires>? "
                    "ORDER BY created,tenant,job LIMIT 1", (t,),
                ).fetchone()
                if not row:
                    db.execute("COMMIT")
                    return None
                tenant, job, hostname, proof, expiry = row
                try:
                    proofs.require_dns_verified(tenant, proof, now=t)
                    verified = proofs.get_verified(tenant, proof, now=t)
                    if verified.hostname != hostname:
                        raise ProofError("Durable job hostname/proof mismatch")
                except ProofError:
                    db.execute(
                        "UPDATE jobs SET state='denied',updated=? "
                        "WHERE tenant=? AND job=?", (t, tenant, job),
                    )
                    db.execute(
                        "INSERT INTO events VALUES (?,?,?,?)",
                        (tenant, job, t, "denied"),
                    )
                    continue
                break
            token = secrets.token_urlsafe(32)
            db.execute(
                "UPDATE jobs SET state='running',worker=?,lease_digest=?,"
                "lease_expires=?,updated=? WHERE tenant=? AND job=?",
                (worker, hashlib.sha256(token.encode()).hexdigest(),
                 min(t + 30, expiry), t, tenant, job),
            )
            db.execute(
                "INSERT INTO events VALUES (?,?,?,?)", (tenant, job, t, "running"),
            )
            db.execute("COMMIT")
        return Claim(tenant, job, hostname, proof, token)

    def finish(
        self, claim: Claim, *, worker: str, state: str,
        bytes_count: int | None = None, sha256: str | None = None,
        proofs: SqliteOwnershipRegistry, now: int | None = None,
    ) -> None:
        worker = _identifier(worker)
        t = int(time.time()) if now is None else int(now)
        if state not in ("completed", "denied", "failed"):
            raise ValueError("Invalid terminal state")
        if state == "completed":
            if (
                type(bytes_count) is not int or not 0 <= bytes_count <= 1_000_000
                or not isinstance(sha256, str)
                or re.fullmatch(r"[a-f0-9]{64}", sha256) is None
            ):
                raise ValueError("Only bounded byte count and SHA accepted")
        elif bytes_count is not None or sha256 is not None:
            raise ValueError("Failure cannot retain response metadata")
        # The caller-supplied Claim is not trusted for ownership decisions:
        # bind the lease to the durable job's hostname and proof, not fields
        # that a worker can replace while retaining a valid lease token.
        revoked = False
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire(db, t)
            row = db.execute(
                "SELECT hostname,proof FROM jobs WHERE tenant=? AND job=? "
                "AND worker=? AND state='running' AND lease_digest=? "
                "AND lease_expires>? AND expires>?",
                (claim.tenant, claim.job, worker,
                 hashlib.sha256(claim.token.encode()).hexdigest(), t, t),
            ).fetchone()
            if row is None:
                db.execute("COMMIT")
                raise ProofError("Expired or unauthorized worker lease")
            if row != (claim.hostname, claim.proof):
                db.execute("COMMIT")
                raise ProofError("Worker claim does not match durable job")
            if state == "completed":
                try:
                    proofs.require_dns_verified(claim.tenant, row[1], now=t)
                    verified = proofs.get_verified(claim.tenant, row[1], now=t)
                    if verified.hostname != row[0]:
                        raise ProofError("Durable job hostname/proof mismatch")
                except ProofError:
                    revoked = True
                    state = "denied"
                    bytes_count = None
                    sha256 = None
            changed = db.execute(
                "UPDATE jobs SET state=?,bytes_count=?,sha256=?,updated=?,"
                "lease_digest=NULL,lease_expires=NULL WHERE tenant=? "
                "AND job=? AND worker=? AND state='running' AND lease_digest=? "
                "AND lease_expires>? AND expires>?",
                (state, bytes_count, sha256, t, claim.tenant, claim.job,
                 worker, hashlib.sha256(claim.token.encode()).hexdigest(), t, t),
            )
            if changed.rowcount != 1:
                # Persist any timeout transition recorded before lease check.
                db.execute("COMMIT")
                raise ProofError("Expired or unauthorized worker lease")
            db.execute(
                "INSERT INTO events VALUES (?,?,?,?)",
                (claim.tenant, claim.job, t, state),
            )
            db.execute("COMMIT")
        if revoked:
            raise ProofError("Real DNS ownership proof required")

    def reconcile_revocations(
        self, *, proofs: SqliteOwnershipRegistry,
        now: int | None = None, limit: int = 100,
    ) -> int:
        """Fail closed for locally observed revoked/expired DNS proofs.

        Internal maintenance only. This is not a distributed atomic
        revocation barrier; workers must still recheck before egress.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Invalid reconciliation batch size")
        t = int(time.time()) if now is None else int(now)
        denied = 0
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire(db, t)
            # Durable lexicographic cursor; wrap to the beginning after
            # the last active row. A bounded pass eventually visits all
            # active jobs even when the healthy prefix never changes.
            cursor = db.execute(
                "SELECT created,tenant,job FROM maintenance_cursor "
                "WHERE name='revocations'",
            ).fetchone()
            if cursor is None:
                rows = db.execute(
                    "SELECT created,tenant,job,proof,hostname FROM jobs "
                    "WHERE state IN ('queued','running') "
                    "ORDER BY created,tenant,job LIMIT ?", (limit,),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT created,tenant,job,proof,hostname FROM jobs "
                    "WHERE state IN ('queued','running') "
                    "AND (created,tenant,job)>(?,?,?) "
                    "ORDER BY created,tenant,job LIMIT ?",
                    (*cursor, limit),
                ).fetchall()
                if len(rows) < limit:
                    rows += db.execute(
                        "SELECT created,tenant,job,proof,hostname FROM jobs "
                        "WHERE state IN ('queued','running') "
                        "AND (created,tenant,job)<=(?,?,?) "
                        "ORDER BY created,tenant,job LIMIT ?",
                        (*cursor, limit - len(rows)),
                    ).fetchall()
            if rows:
                last = rows[-1][:3]
                db.execute(
                    "INSERT INTO maintenance_cursor(name,created,tenant,job) "
                    "VALUES ('revocations',?,?,?) ON CONFLICT(name) "
                    "DO UPDATE SET created=excluded.created,"
                    "tenant=excluded.tenant,job=excluded.job", last,
                )
            for _, tenant, job, proof, hostname in rows:
                try:
                    proofs.require_dns_verified(tenant, proof, now=t)
                    verified = proofs.get_verified(tenant, proof, now=t)
                    if verified.hostname != hostname:
                        raise ProofError("Durable job hostname/proof mismatch")
                except ProofError:
                    db.execute(
                        "UPDATE jobs SET state='denied',updated=?,"
                        "lease_digest=NULL,lease_expires=NULL "
                        "WHERE tenant=? AND job=? AND state IN ('queued','running')",
                        (t, tenant, job),
                    )
                    db.execute(
                        "INSERT INTO events VALUES (?,?,?,?)",
                        (tenant, job, t, "denied"),
                    )
                    denied += 1
            db.execute("COMMIT")
        return denied

    def status(self, tenant: str, job: str) -> tuple[str, int | None, str | None]:
        tenant, job = _identifier(tenant), _identifier(job)
        with self._db() as db:
            row = db.execute(
                "SELECT state,bytes_count,sha256 FROM jobs "
                "WHERE tenant=? AND job=?", (tenant, job),
            ).fetchone()
        if row is None:
            raise ProofError("Job unavailable")
        return row

    def events(self, tenant: str, job: str) -> list[tuple[int, str]]:
        self.status(tenant, job)
        with self._db() as db:
            return db.execute(
                "SELECT moment,state FROM events WHERE tenant=? AND job=? "
                "ORDER BY rowid LIMIT 1000", (tenant, job),
            ).fetchall()

    def prune(
        self, *, now: int | None = None, days: int = 30, limit: int = 500,
    ) -> int:
        if not 1 <= days <= 90 or not 1 <= limit <= 1000:
            raise ValueError("Invalid retention")
        t = int(time.time()) if now is None else int(now)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire(db, t)
            stale = db.execute(
                "SELECT tenant,job FROM jobs WHERE "
                "state NOT IN ('queued','running') AND updated<? "
                "ORDER BY updated LIMIT ?",
                (t - 86400 * days, limit),
            ).fetchall()
            for tenant, job in stale:
                db.execute(
                    "DELETE FROM jobs WHERE tenant=? AND job=?", (tenant, job),
                )
            db.execute("COMMIT")
        return len(stale)
