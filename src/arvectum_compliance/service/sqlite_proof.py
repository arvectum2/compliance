"""Durable, transactional domain proof registry for a single trusted service.

Store only challenge hashes. No plaintext nonce, cookie or personal data.
This is NOT a public API; tenant identity must be enforced by the caller.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from .domain_proof import (
    _MAX_TTL,
    _TXT_PREFIX,
    PendingProof,
    ProofError,
    VerifiedProof,
    _identifier,
    canonical_hostname,
)


class SqliteOwnershipRegistry:
    def __init__(self, database: str | Path) -> None:
        self._path = Path(database)
        if self._path.is_symlink() or not self._path.parent.is_dir():
            raise ProofError("Unsafe database file path")
        try:
            fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        mode = self._path.stat().st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise ProofError("Proof store must be a private regular file (0600)")
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS domain_proofs (
                    id TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    challenge_hash TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'verified', 'revoked')),
                    verified_method TEXT NOT NULL DEFAULT 'legacy'
                )
            """)
            columns = {
                row[1] for row in db.execute("PRAGMA table_info(domain_proofs)")
            }
            if "verified_method" not in columns:
                db.execute(
                    "ALTER TABLE domain_proofs ADD COLUMN verified_method "
                    "TEXT NOT NULL DEFAULT 'legacy'"
                )

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self._path, timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA busy_timeout=5000")
            yield db
        finally:
            db.close()

    def issue(self, tenant_id: str, hostname: str, *, now: int | None = None) -> PendingProof:
        tenant_id = _identifier(tenant_id)
        hostname = canonical_hostname(hostname)
        current = int(time.time()) if now is None else int(now)
        challenge_id, nonce = secrets.token_hex(16), secrets.token_urlsafe(32)
        expires_at = current + _MAX_TTL
        digest = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        with self._connect() as db:
            db.execute(
                "INSERT INTO domain_proofs "
                "(id, tenant, hostname, challenge_hash, expires_at, status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (challenge_id, tenant_id, hostname, digest, expires_at, "pending"),
            )
        return PendingProof(
            challenge_id, tenant_id, hostname, f"_arvectum-compliance.{hostname}",
            f"{_TXT_PREFIX}{challenge_id}.{nonce}", expires_at,
        )

    def confirm(
        self, tenant_id: str, proof_id: str,
        txt_lookup: Callable[[str], list[str] | tuple[str, ...]],
        *, now: int | None = None, verification_method: str = "offline-test",
    ) -> VerifiedProof:
        if verification_method not in ("offline-test", "doh-quorum"):
            raise ProofError("Unknown DNS ownership verification method")
        tenant_id = _identifier(tenant_id)
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            row = db.execute(
                "SELECT tenant, hostname, challenge_hash, expires_at, status "
                "FROM domain_proofs WHERE id=?", (proof_id,),
            ).fetchone()
            if row is None or row[0] != tenant_id or row[4] != "pending" or current >= row[3]:
                raise ProofError("Proof unavailable or expired")
            hostname, digest, expires_at = row[1], row[2], row[3]
        records = txt_lookup(f"_arvectum-compliance.{hostname}")
        if not isinstance(records, (list, tuple)) or len(records) > 64:
            raise ProofError("Invalid DNS TXT lookup result")
        prefix = f"{_TXT_PREFIX}{proof_id}."
        found = False
        for txt in records:
            if not isinstance(txt, str) or len(txt) > 512:
                raise ProofError("Invalid DNS TXT record")
            if txt.startswith(prefix):
                candidate = hashlib.sha256(txt[len(prefix):].encode("utf-8")).hexdigest()
                found |= hmac.compare_digest(candidate, digest)
        if not found:
            raise ProofError("Domain challenge not found")
        with self._connect() as db:
            cur = db.execute(
                "UPDATE domain_proofs SET status='verified', verified_method=? "
                "WHERE id=? AND tenant=? AND status='pending' AND expires_at>?",
                (verification_method, proof_id, tenant_id, current),
            )
            if cur.rowcount != 1:
                raise ProofError("Challenge already consumed, expired or revoked")
        return VerifiedProof(proof_id, tenant_id, hostname, expires_at)

    def check(self, proof: VerifiedProof, *, now: int | None = None) -> None:
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            row = db.execute(
                "SELECT tenant, hostname, expires_at, status "
                "FROM domain_proofs WHERE id=?", (proof.id,),
            ).fetchone()
        if (
            row is None or row != (
                proof.tenant_id, proof.hostname, proof.expires_at, "verified"
            ) or current >= proof.expires_at
        ):
            raise ProofError("Verified domain ownership is no longer active")

    def require_dns_verified(
        self, tenant_id: str, proof_id: str, *, now: int | None = None,
    ) -> None:
        """Only true dual-DoH proofs authorize non-fixture network requests.

        Legacy/migrated proofs and injected offline resolvers are NO-GO.
        """
        tenant_id = _identifier(tenant_id)
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            row = db.execute(
                "SELECT status, verified_method, expires_at FROM domain_proofs "
                "WHERE id=? AND tenant=?", (proof_id, tenant_id),
            ).fetchone()
        if (
            row is None or row[0] != "verified"
            or row[1] != "doh-quorum" or current >= row[2]
        ):
            raise ProofError("Real DNS ownership proof required")

    def require_dns_verified_host(
        self, tenant_id: str, proof_id: str, hostname: str,
        *, now: int | None = None,
    ) -> None:
        """Single-snapshot proof, method, expiry and exact-host check.

        Avoids the two-query race between require_dns_verified and
        get_verified. Does NOT make job DB and proof DB atomic.
        """
        tenant_id = _identifier(tenant_id)
        hostname = canonical_hostname(hostname)
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            row = db.execute(
                "SELECT status,verified_method,expires_at,hostname "
                "FROM domain_proofs WHERE id=? AND tenant=?",
                (proof_id, tenant_id),
            ).fetchone()
        if (
            row is None or row[0] != "verified"
            or row[1] != "doh-quorum" or current >= row[2]
            or row[3] != hostname
        ):
            raise ProofError("Real DNS ownership proof/hostname required")

    def get_verified(
        self, tenant_id: str, proof_id: str, *, now: int | None = None,
    ) -> VerifiedProof:
        """Read a current tenant-bound proof from persistent trusted storage."""
        tenant_id = _identifier(tenant_id)
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            row = db.execute(
                "SELECT hostname, expires_at, status FROM domain_proofs "
                "WHERE id=? AND tenant=?", (proof_id, tenant_id),
            ).fetchone()
        if row is None or row[2] != "verified" or current >= row[1]:
            raise ProofError("Verified proof unavailable")
        return VerifiedProof(proof_id, tenant_id, row[0], row[1])

    def revoke(self, tenant_id: str, proof_id: str) -> None:
        tenant_id = _identifier(tenant_id)
        with self._connect() as db:
            result = db.execute(
                "UPDATE domain_proofs SET status='revoked' WHERE id=? AND tenant=?",
                (proof_id, tenant_id),
            )
            if result.rowcount != 1:
                raise ProofError("Proof unavailable")
