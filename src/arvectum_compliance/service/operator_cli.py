"""Private operator CLI. Never expose these commands through a public API.

All secret material resides in a 0700 local directory. Access tokens and
signed scan capabilities are written to 0600 files, never printed to logs.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from dataclasses import asdict
from pathlib import Path

from .authorization import GrantIssuer
from .domain_proof import ProofError, _identifier
from .sqlite_proof import SqliteOwnershipRegistry
from .tenant_auth import SCOPES, TenantAuth
from .verified_jobs import VerifiedScanService


def _private_dir(path: Path, *, create: bool = False) -> Path:
    if path.is_symlink():
        raise ProofError("Symlinked secret directory refused")
    if create and not path.exists():
        path.mkdir(mode=0o700, parents=False)
    if not path.is_dir() or path.stat().st_mode & 0o077:
        raise ProofError("Secret directory must have mode 0700")
    return path


def _read_secret(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ProofError("Unsafe secret file")
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077:
        raise ProofError("Secret file must have mode 0600")
    contents = path.read_bytes()
    if not contents or len(contents) > 512:
        raise ProofError("Invalid secret file")
    return contents


def _write_secret(path: Path, body: bytes) -> None:
    if path.is_symlink():
        raise ProofError("Symlinked secret file refused")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _service(root: Path) -> VerifiedScanService:
    root = _private_dir(root)
    signing_path = root / "signing.key"
    if not signing_path.exists():
        _write_secret(signing_path, secrets.token_bytes(32))
    signing = _read_secret(signing_path)
    if len(signing) != 32:
        raise ProofError("Invalid signing key")
    auth = TenantAuth(root / "access.db")
    proofs = SqliteOwnershipRegistry(root / "ownership.db")
    return VerifiedScanService(auth, proofs, GrantIssuer(proofs, signing))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="arvectum-compliance-admin")
    parser.add_argument("--state-dir", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    provision = commands.add_parser("provision", help="Local trusted administrator ONLY")
    provision.add_argument("--tenant", required=True)
    challenge = commands.add_parser("challenge")
    challenge.add_argument("--token-file", type=Path, required=True)
    challenge.add_argument("--host", required=True)
    confirm = commands.add_parser("confirm")
    confirm.add_argument("--token-file", type=Path, required=True)
    confirm.add_argument("--proof-id", required=True)
    grant = commands.add_parser("grant")
    grant.add_argument("--token-file", type=Path, required=True)
    grant.add_argument("--proof-id", required=True)
    grant.add_argument("--job-id", required=True)
    grant.add_argument("--output", type=Path, required=True)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--token-file", type=Path, required=True)
    revoke.add_argument("--proof-id", required=True)
    audit = commands.add_parser("ledger-audit", help="Offline read-only job ledger preflight")
    audit.add_argument("--limit", type=int, default=1000)
    commands.add_parser("attestor-init", help="Initialize private Ed25519 signing identity")
    commands.add_parser("attestor-info", help="Show public signing-key fingerprint")
    rotation = commands.add_parser(
        "attestor-rotate", help="Offline key rotation; requires explicit acknowledgement",
    )
    rotation.add_argument("--confirm-rotation", action="store_true")
    recover = commands.add_parser(
        "attestor-recover", help="Explicitly clean abandoned rotation artifacts",
    )
    recover.add_argument("--confirm-recovery", action="store_true")
    smoke = commands.add_parser("verified-root", help="Single verified root HTTPS GET")
    smoke.add_argument("--token-file", type=Path, required=True)
    smoke.add_argument("--proof-id", required=True)
    smoke.add_argument("--job-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "provision":
            root = _private_dir(args.state_dir, create=True)
        else:
            root = _private_dir(args.state_dir)
        if args.command == "ledger-audit":
            from .job_ledger import JobLedger

            path = root / "jobs.db"
            if path.is_symlink() or not path.is_file():
                raise ProofError("Missing or unsafe job database")
            mode = path.stat().st_mode
            if not stat.S_ISREG(mode) or mode & 0o777 != 0o600:
                raise ProofError("Job store must be private regular file")
            # Avoid JobLedger.__init__: it creates files and runs schema DDL.
            ledger = object.__new__(JobLedger)
            ledger.path = path
            result = ledger.audit_integrity(limit=args.limit)
            passed = bool(result["complete"] and not result["anomalies"])
            print(json.dumps({**result, "gate": "PASS" if passed else "NO-GO"},
                             sort_keys=True))
            return 0 if passed else 3
        service = _service(root)
        if args.command == "provision":
            tenant = _identifier(args.tenant)
            token_path = root / f"tenant-{tenant}.token"
            if token_path.exists() or token_path.is_symlink():
                raise ProofError("Tenant token file already exists")
            token = service.auth.issue(tenant, scopes=frozenset(SCOPES))
            _write_secret(token_path, token.encode("ascii"))
            print(json.dumps({"tenant": tenant, "token_file": str(token_path)}))
            return 0
        if args.command in (
            "attestor-init", "attestor-info", "attestor-rotate", "attestor-recover",
        ):
            from .attestor_keys import load_attestor_identity
            from .attestor_rotation import (
                recover_attestor_state,
                rotate_attestor_identity,
            )

            recovered = 0
            if args.command == "attestor-recover":
                if not args.confirm_recovery:
                    raise ProofError("Explicit recovery acknowledgement required")
                identity, recovered = recover_attestor_state(root)
            elif args.command == "attestor-rotate":
                if not args.confirm_rotation:
                    raise ProofError("Explicit rotation acknowledgement required")
                identity = rotate_attestor_identity(root)
            else:
                identity = load_attestor_identity(
                    root, initialize=args.command == "attestor-init",
                )
            print(json.dumps({
                "public_fingerprint": identity.public_fingerprint,
                "public_key_file": str(identity.public_path),
                "generation": identity.generation,
                "cleaned_orphan_files": recovered,
            }, sort_keys=True))
            return 0
        token = _read_secret(args.token_file).decode("ascii")
        if args.command == "verified-root":
            from .attestor_keys import load_attestor_identity
            from .verified_root import run_verified_root

            identity = load_attestor_identity(root)
            result = run_verified_root(
                service, identity, token, args.proof_id, args.job_id,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "challenge":
            result = service.issue_challenge(token, args.host)
            print(json.dumps(asdict(result), sort_keys=True))
        elif args.command == "confirm":
            result = service.confirm_challenge(token, args.proof_id)
            print(json.dumps(asdict(result), sort_keys=True))
        elif args.command == "grant":
            result = service.authorize_scan(token, args.proof_id, args.job_id)
            _write_secret(args.output, json.dumps(asdict(result), sort_keys=True).encode())
            print(json.dumps({"grant_file": str(args.output)}))
        elif args.command == "revoke":
            service.revoke_domain(token, args.proof_id)
            print('{"status":"revoked"}')
        return 0
    except (ProofError, OSError, UnicodeError, ValueError, RuntimeError) as exc:
        # Never show bearer token or exact sensitive files in raw error strings.
        print(f"ERROR: {type(exc).__name__}; operator action failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
