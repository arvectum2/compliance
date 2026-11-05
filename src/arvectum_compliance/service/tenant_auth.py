"""Private, durable token/RBAC gate for the trusted control plane.

Not an HTTP service or user registration system. Tokens are random 256-bit
bearer capabilities, stored only as SHA-256 digests in private SQLite.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .domain_proof import ProofError, _identifier

SCOPES = frozenset({"domain:verify", "scan:create", "domain:revoke"})
MAX_TTL = 7 * 86400


@dataclass(frozen=True, slots=True)
class Principal:
    tenant_id: str
    scopes: frozenset[str]
    expires_at: int


class TenantAuth:
    def __init__(self, database: str | Path):
        self.path = Path(database)
        if self.path.is_symlink() or not self.path.parent.is_dir():
            raise ProofError("Unsafe credential store path")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        mode = self.path.stat().st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise ProofError("Credential store must be a private regular file (0600)")
        with sqlite3.connect(self.path) as db:
            db.execute("""
            CREATE TABLE IF NOT EXISTS access_tokens(
                digest TEXT PRIMARY KEY, tenant TEXT NOT NULL,
                scopes TEXT NOT NULL, expires INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )""")
            db.execute("""
            CREATE TABLE IF NOT EXISTS quota_windows(
                tenant TEXT NOT NULL, action TEXT NOT NULL,
                window_start INTEGER NOT NULL, count INTEGER NOT NULL,
                PRIMARY KEY(tenant, action, window_start)
            )""")

    def issue(
        self, tenant_id: str, *, scopes: frozenset[str],
        ttl: int = 3600, now: int | None = None,
    ) -> str:
        """Provision tokens only from a separate trusted administrator."""
        tenant_id = _identifier(tenant_id)
        if not scopes or not scopes <= SCOPES or not 1 <= ttl <= MAX_TTL:
            raise ValueError("Invalid scopes or access-token expiry")
        current = int(time.time()) if now is None else int(now)
        token = "acp_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute(
                "INSERT INTO access_tokens VALUES (?,?,?,?,0)",
                (digest, tenant_id, ",".join(sorted(scopes)), current + ttl),
            )
        return token

    def require(
        self, token: str, scope: str, *, now: int | None = None,
    ) -> Principal:
        if (
            not isinstance(token, str) or not token.startswith("acp_")
            or len(token) > 100 or scope not in SCOPES
        ):
            raise ProofError("Access denied")
        current = int(time.time()) if now is None else int(now)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with sqlite3.connect(self.path, timeout=5) as db:
            row = db.execute(
                "SELECT tenant, scopes, expires, revoked FROM access_tokens WHERE digest=?",
                (digest,),
            ).fetchone()
        if row is None or row[3] or row[2] <= current:
            raise ProofError("Access denied")
        scopes = frozenset(row[1].split(","))
        if scope not in scopes:
            raise ProofError("Access denied")
        return Principal(row[0], scopes, row[2])

    def revoke(self, token: str) -> None:
        if not isinstance(token, str) or not token.startswith("acp_"):
            raise ProofError("Access denied")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with sqlite3.connect(self.path, timeout=5) as db:
            changed = db.execute(
                "UPDATE access_tokens SET revoked=1 WHERE digest=?", (digest,),
            )
            if changed.rowcount != 1:
                raise ProofError("Access denied")

    def charge(
        self, principal: Principal, action: str, *,
        limit: int, now: int | None = None,
    ) -> None:
        """Atomic per-tenant hourly quota, including failed challenge attempts."""
        if action not in SCOPES or not 1 <= limit <= 1000:
            raise ValueError("Invalid quota")
        current = int(time.time()) if now is None else int(now)
        if current >= principal.expires_at:
            raise ProofError("Access denied")
        window = current - current % 3600
        with sqlite3.connect(self.path, timeout=5, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute(
                "SELECT count FROM quota_windows WHERE tenant=? AND action=? "
                "AND window_start=?",
                (principal.tenant_id, action, window),
            ).fetchone()
            if count is not None and count[0] >= limit:
                db.execute("ROLLBACK")
                raise ProofError("Tenant action quota exceeded")
            db.execute(
                "INSERT INTO quota_windows VALUES(?,?,?,1) "
                "ON CONFLICT(tenant, action, window_start) DO UPDATE SET count=count+1",
                (principal.tenant_id, action, window),
            )
            db.execute("COMMIT")
