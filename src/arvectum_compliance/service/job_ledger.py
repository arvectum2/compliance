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
from .domain_proof import ProofError, _identifier, canonical_hostname
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
            CREATE INDEX IF NOT EXISTS jobs_expiry_idx
              ON jobs(state,expires);
            CREATE INDEX IF NOT EXISTS jobs_lease_expiry_idx
              ON jobs(state,lease_expires);
            CREATE INDEX IF NOT EXISTS jobs_tenant_active_idx
              ON jobs(tenant,state,expires,lease_expires);
            CREATE INDEX IF NOT EXISTS jobs_terminal_retention_idx
              ON jobs(state,updated);
            CREATE TABLE IF NOT EXISTS maintenance_cursor(
              name TEXT PRIMARY KEY, created INTEGER NOT NULL,
              tenant TEXT NOT NULL, job TEXT NOT NULL);
            """)

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _expire(
        db: sqlite3.Connection, t: int, *, limit: int = 500,
    ) -> int:
        """Bound maintenance work; callers independently filter expired jobs."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Invalid expiry batch size")
        expired = db.execute(
            "SELECT tenant,job FROM jobs WHERE "
            "(state='queued' AND expires<=?) OR "
            "(state='running' AND (lease_expires<=? OR expires<=?))",
            (t, t, t),
        ).fetchmany(limit)
        for tenant, job in expired:
            db.execute(
                "UPDATE jobs SET state='expired',updated=?,lease_digest=NULL,"
                "lease_expires=NULL WHERE tenant=? AND job=?", (t, tenant, job),
            )
            db.execute(
                "INSERT INTO events VALUES (?,?,?,?)", (tenant, job, t, "expired"),
            )
        return len(expired)

    def expire_batch(
        self, *, now: int | None = None, limit: int = 500,
    ) -> int:
        """Explicit bounded expiry sweep for an internal maintenance loop."""
        t = int(time.time()) if now is None else int(now)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = self._expire(db, t, limit=limit)
            db.execute("COMMIT")
        return changed

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
        proofs.require_dns_verified_host(
            grant.tenant_id, grant.proof_id, grant.hostname, now=t,
        )
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
                    "AND ((state='queued' AND expires>?) "
                    "OR (state='running' AND expires>? AND lease_expires>?))",
                    (grant.tenant_id, t, t, t),
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
        now: int | None = None, rejection_limit: int = 100,
    ) -> Claim | None:
        """Claim at most one valid job after bounded invalid-proof denials.

        A revoked FIFO prefix must not hold a SQLite write lock without
        limit. Callers can retry after a None result to drain the backlog.
        """
        worker = _identifier(worker)
        if type(rejection_limit) is not int or not 1 <= rejection_limit <= 1000:
            raise ValueError("Invalid claim rejection limit")
        t = int(time.time()) if now is None else int(now)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire(db, t)
            for _ in range(rejection_limit + 1):
                row = db.execute(
                    "SELECT tenant,job,hostname,proof,expires FROM jobs "
                    "WHERE state='queued' AND expires>? "
                    "ORDER BY created,tenant,job LIMIT 1", (t,),
                ).fetchone()
                if not row:
                    db.execute("COMMIT")
                    return None
                if _ == rejection_limit:
                    db.execute("COMMIT")
                    return None
                tenant, job, hostname, proof, expiry = row
                try:
                    proofs.require_dns_verified_host(
                        tenant, proof, hostname, now=t,
                    )
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
            else:
                db.execute("COMMIT")
                return None
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
                    proofs.require_dns_verified_host(
                        claim.tenant, row[1], row[0], now=t,
                    )
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
                    "WHERE ((state='queued' AND expires>?) "
                    "OR (state='running' AND expires>? AND lease_expires>?)) "
                    "ORDER BY created,tenant,job LIMIT ?", (t, t, t, limit),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT created,tenant,job,proof,hostname FROM jobs "
                    "WHERE ((state='queued' AND expires>?) "
                    "OR (state='running' AND expires>? AND lease_expires>?)) "
                    "AND (created,tenant,job)>(?,?,?) "
                    "ORDER BY created,tenant,job LIMIT ?",
                    (t, t, t, *cursor, limit),
                ).fetchall()
                if len(rows) < limit:
                    rows += db.execute(
                        "SELECT created,tenant,job,proof,hostname FROM jobs "
                        "WHERE ((state='queued' AND expires>?) "
                        "OR (state='running' AND expires>? AND lease_expires>?)) "
                        "AND (created,tenant,job)<=(?,?,?) "
                        "ORDER BY created,tenant,job LIMIT ?",
                        (t, t, t, *cursor, limit - len(rows)),
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
                    proofs.require_dns_verified_host(
                        tenant, proof, hostname, now=t,
                    )
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

    def audit_integrity(self, *, limit: int = 1000) -> dict[str, int]:
        """Bounded, read-only internal integrity preflight; never repairs data.

        Returns only aggregate counts. Any anomaly must block worker startup;
        this is not a substitute for authenticated distributed coordination.
        """
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("Invalid audit limit")
        with self._db() as db:
            # All checks must observe one SQLite snapshot. Without an explicit
            # read transaction, concurrent maintenance can change jobs/events
            # between queries and produce a false clean or false anomaly.
            db.execute("BEGIN")
            result = db.execute("PRAGMA quick_check(1)").fetchone()
            if result is None or result[0] != "ok":
                raise ProofError("Job database integrity check failed")
            # A bounded scan is explicitly incomplete for larger stores.
            total = db.execute("SELECT count(*) FROM jobs").fetchone()[0]
            rows = db.execute(
                "SELECT tenant,job,hostname,proof,grant_digest,state,"
                "worker,lease_digest,lease_expires,bytes_count,sha256,"
                "expires,created,updated,"
                "(SELECT state FROM events WHERE events.tenant=jobs.tenant "
                "AND events.job=jobs.job ORDER BY rowid DESC LIMIT 1),"
                "(SELECT moment FROM events WHERE events.tenant=jobs.tenant "
                "AND events.job=jobs.job ORDER BY rowid DESC LIMIT 1) "
                "FROM jobs ORDER BY tenant,job LIMIT ?", (limit,),
            ).fetchall()
            # Detect orphaned journal rows even when the parent job was
            # deleted with foreign-key enforcement disabled. The anti-join
            # stops at the first orphan and never returns sensitive payloads.
            orphan = db.execute(
                "SELECT 1 FROM events e WHERE NOT EXISTS ("
                "SELECT 1 FROM jobs j WHERE j.tenant=e.tenant AND j.job=e.job"
                ") LIMIT 1"
            ).fetchone()
            # A missing journal for a job beyond the bounded scan must
            # also fail closed. Do not expose job identifiers.
            missing_history = db.execute(
                "SELECT 1 FROM jobs j WHERE NOT EXISTS ("
                "SELECT 1 FROM events e WHERE e.tenant=j.tenant "
                "AND e.job=j.job) LIMIT 1"
            ).fetchone()
            # The bounded job scan can miss malformed historical events.
            # Check journal state and chronology globally without returning
            # payloads; the first violation is enough to fail the preflight.
            invalid_event = db.execute(
                "SELECT 1 FROM events e JOIN jobs j "
                "ON j.tenant=e.tenant AND j.job=e.job "
                "WHERE e.state NOT IN "
                "('queued','running','completed','denied','failed','expired') "
                "OR typeof(e.moment) != 'integer' "
                "OR e.moment < j.created OR e.moment > j.updated "
                "LIMIT 1"
            ).fetchone()
            # Journal order is append-only by rowid. A history must begin
            # queued, and timestamps must never move backwards. This catches
            # forged intermediate transitions even if the latest row matches.
            invalid_history = db.execute(
                "SELECT 1 FROM ("
                "SELECT state,moment,"
                "LAG(state) OVER (PARTITION BY tenant,job ORDER BY rowid) "
                "AS previous_state,"
                "LAG(moment) OVER (PARTITION BY tenant,job ORDER BY rowid) "
                "AS previous_moment,"
                "ROW_NUMBER() OVER (PARTITION BY tenant,job ORDER BY rowid) "
                "AS position FROM events"
                ") WHERE (position=1 AND state!='queued') "
                "OR (previous_moment IS NOT NULL AND moment<previous_moment) "
                "OR (previous_state='queued' AND state NOT IN "
                "('running','denied','expired')) "
                "OR (previous_state='running' AND state NOT IN "
                "('completed','denied','failed','expired')) "
                "OR (previous_state IN ('completed','denied','failed','expired')) "
                "LIMIT 1"
            ).fetchone()
            # Detect latest-event divergence for every job, not just the
            # bounded detailed sample. Never return tenant or job identifiers.
            stale_head = db.execute(
                "SELECT 1 FROM jobs j WHERE (j.tenant,j.job) > (?,?) AND EXISTS ("
                "SELECT 1 FROM events e WHERE e.tenant=j.tenant "
                "AND e.job=j.job AND e.rowid=("
                "SELECT max(e2.rowid) FROM events e2 "
                "WHERE e2.tenant=j.tenant AND e2.job=j.job) "
                "AND (e.state IS NOT j.state OR e.moment IS NOT j.updated)"
                ") LIMIT 1", (rows[-1][0], rows[-1][1]),
            ).fetchone() if rows and total > len(rows) else None
            # Reject malformed grant digests outside the detailed sample too.
            # A forged digest must not be hidden behind a small audit limit.
            invalid_digest = db.execute(
                "SELECT 1 FROM jobs j WHERE (j.tenant,j.job) > (?,?) "
                "AND (typeof(j.grant_digest) != 'text' "
                "OR length(j.grant_digest) != 64 "
                "OR j.grant_digest GLOB '*[^0-9a-f]*') LIMIT 1",
                (rows[-1][0], rows[-1][1]),
            ).fetchone() if rows and total > len(rows) else None
            # Sampled identity checks must not allow malformed identifiers or
            # noncanonical hostnames to hide in the unsampled tail. SQLite
            # GLOB checks are only a fast filter; Python validates canonical
            # hostnames and identifiers without exposing their values.
            invalid_identity = False
            if rows and total > len(rows):
                tail = db.execute(
                    "SELECT tenant,job,proof,hostname FROM jobs "
                    "WHERE (tenant,job) > (?,?) ORDER BY tenant,job",
                    (rows[-1][0], rows[-1][1]),
                )
                for tail_tenant, tail_job, tail_proof, tail_host in tail:
                    try:
                        if (_identifier(tail_tenant) != tail_tenant
                             or _identifier(tail_job) != tail_job
                             or _identifier(tail_proof) != tail_proof
                             or canonical_hostname(tail_host) != tail_host):
                            invalid_identity = True
                            break
                    except (ProofError, TypeError, ValueError):
                        invalid_identity = True
                        break
            # Even a bounded detailed audit must fail closed when an
            # unsampled job has inconsistent worker/lease/result metadata.
            # This is an offline diagnostic, not a distributed lease gate.
            invalid_tail_metadata = db.execute(
                "SELECT 1 FROM jobs j WHERE (j.tenant,j.job) > (?,?) AND ("
                "j.state NOT IN ('queued','running','completed','denied','failed','expired') "
                "OR (j.state='queued' AND j.worker IS NOT NULL) "
                "OR (j.state='running' AND ("
                "j.worker IS NULL OR typeof(j.worker)!='text' "
                "OR length(j.worker) NOT BETWEEN 1 AND 100 "
                "OR j.worker GLOB '*[^a-zA-Z0-9_-]*' "
                "OR typeof(j.lease_digest)!='text' "
                "OR length(j.lease_digest)!=64 "
                "OR j.lease_digest GLOB '*[^0-9a-f]*' "
                "OR typeof(j.lease_expires)!='integer' "
                "OR j.lease_expires<=j.created "
                "OR j.lease_expires>j.created+3600 "
                "OR j.lease_expires>j.expires)) "
                "OR (j.state!='running' AND ("
                "j.lease_digest IS NOT NULL OR j.lease_expires IS NOT NULL)) "
                "OR (j.state='completed' AND ("
                "typeof(j.bytes_count)!='integer' "
                "OR j.bytes_count NOT BETWEEN 0 AND 1000000 "
                "OR typeof(j.sha256)!='text' OR length(j.sha256)!=64 "
                "OR j.sha256 GLOB '*[^0-9a-f]*')) "
                "OR (j.state!='completed' AND ("
                "j.bytes_count IS NOT NULL OR j.sha256 IS NOT NULL)) "
                "OR typeof(j.created)!='integer' "
                "OR typeof(j.updated)!='integer' "
                "OR typeof(j.expires)!='integer' "
                "OR j.updated<j.created OR j.expires<=j.created"
                ") LIMIT 1", (rows[-1][0], rows[-1][1]),
            ).fetchone() if rows and total > len(rows) else None
            # The reconciliation cursor is durable control-plane state.
            # Reject malformed or unexpected entries before any future
            # worker startup; never expose the cursor's identifiers.
            invalid_cursor = False
            for name, cursor_created, cursor_tenant, cursor_job in db.execute(
                "SELECT name,created,tenant,job FROM maintenance_cursor"
            ):
                try:
                    if (name != "revocations"
                        or type(cursor_created) is not int
                        or cursor_created < 0
                        or _identifier(cursor_tenant) != cursor_tenant
                        or _identifier(cursor_job) != cursor_job):
                        invalid_cursor = True
                        break
                except (ProofError, TypeError, ValueError):
                    invalid_cursor = True
                    break
            anomalies = (int(invalid_cursor)
                         + int(missing_history is not None)
                         + int(orphan is not None)
                         + int(invalid_event is not None)
                         + int(invalid_history is not None)
                         + int(stale_head is not None)
                         + int(invalid_digest is not None)
                         + int(invalid_identity)
                         + int(invalid_tail_metadata is not None))
            for (
                tenant, job, hostname, proof, grant_digest, state, worker,
                digest, lease, count, sha, expiry, created, updated,
                last_state, last_moment,
            ) in rows:
                try:
                    valid_identity = (
                        _identifier(tenant) == tenant
                        and _identifier(job) == job
                        and _identifier(proof) == proof
                        and canonical_hostname(hostname) == hostname
                    )
                except (ProofError, TypeError, ValueError):
                    valid_identity = False
                active_lease = state == "running"
                bad = (
                    not valid_identity
                    or last_state != state or type(last_moment) is not int
                    or (type(last_moment) is int and last_moment != updated)
                    or not isinstance(grant_digest, str)
                    or re.fullmatch(r"[a-f0-9]{64}", grant_digest) is None
                    or state not in (
                        "queued", "running", "completed", "denied", "failed", "expired"
                    )
                    or (state == "queued" and worker is not None)
                    or (active_lease and (
                        not isinstance(worker, str)
                        or re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", worker) is None
                    ))
                    or (active_lease and (
                        not worker or not isinstance(digest, str)
                        or re.fullmatch(r"[a-f0-9]{64}", digest) is None
                        or type(lease) is not int or lease > expiry
                    ))
                    or (not active_lease and (digest is not None or lease is not None))
                    or (state == "completed" and (
                        type(count) is not int or not 0 <= count <= 1_000_000
                        or not isinstance(sha, str)
                        or re.fullmatch(r"[a-f0-9]{64}", sha) is None
                    ))
                    or (state != "completed" and (count is not None or sha is not None))
                    or type(created) is not int or type(updated) is not int
                    or type(expiry) is not int or updated < created
                    or expiry <= created
                    or (active_lease and (
                        lease <= created or lease > created + 3600
                    ))
                )
                anomalies += bool(bad)
            return {"checked": len(rows), "total": total, "anomalies": anomalies,
                    "complete": int(total <= limit)}
