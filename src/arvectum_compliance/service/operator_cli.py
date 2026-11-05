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
    return contents.strip()


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "provision":
            root = _private_dir(args.state_dir, create=True)
        else:
            root = _private_dir(args.state_dir)
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
        token = _read_secret(args.token_file).decode("ascii")
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
    except (ProofError, OSError, UnicodeError, ValueError) as exc:
        # Never show bearer token or exact sensitive files in raw error strings.
        print(f"ERROR: {type(exc).__name__}; operator action failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
