"""Local persistent Ed25519 signing identity for a private trusted operator.

Never put the private key in a Docker image, mounted container volume or Git.
A proper KMS/HSM is required before multi-node or public use.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .domain_proof import ProofError

_PRIVATE_NAME = "attestor-ed25519.key"
_PUBLIC_NAME = "attestor-ed25519.pub"


def _read_regular(path: Path, *, mode: int, size: int) -> bytes:
    if path.is_symlink():
        raise ProofError("Symlinked signing key refused")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o777 != mode or st.st_size != size:
            raise ProofError("Invalid signing key file permissions or size")
        data = os.read(fd, size + 1)
    finally:
        os.close(fd)
    if len(data) != size:
        raise ProofError("Invalid signing key data")
    return data


def _exclusive_private_file(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _secure_state_directory(path: Path) -> Path:
    if (
        path.is_symlink() or not path.is_dir()
        or path.stat().st_mode & 0o777 != 0o700
    ):
        raise ProofError("Signing key directory must be private mode 0700")
    return path


@dataclass(frozen=True)
class AttestorIdentity:
    private: Ed25519PrivateKey
    public_path: Path
    public_fingerprint: str


def load_attestor_identity(state_dir: str | Path, *, initialize: bool = False) -> AttestorIdentity:
    """Initialize exactly once; never silently replace a missing key after setup."""
    import hashlib

    root = _secure_state_directory(Path(state_dir))
    private_path = root / _PRIVATE_NAME
    public_path = root / _PUBLIC_NAME
    if initialize:
        if (
            private_path.exists() or private_path.is_symlink()
            or public_path.exists() or public_path.is_symlink()
        ):
            raise ProofError("Attestor signing identity already exists; rotation is explicit")
        key = Ed25519PrivateKey.generate()
        _exclusive_private_file(private_path, key.private_bytes_raw(), 0o600)
        try:
            _exclusive_private_file(public_path, key.public_key().public_bytes_raw(), 0o644)
        except Exception:
            # Never silently regenerate: leave private key and require recovery.
            raise
    raw = _read_regular(private_path, mode=0o600, size=32)
    public = _read_regular(public_path, mode=0o644, size=32)
    private = Ed25519PrivateKey.from_private_bytes(raw)
    if public != private.public_key().public_bytes_raw():
        raise ProofError("Attestor public key does not match private key")
    return AttestorIdentity(
        private=private,
        public_path=public_path,
        public_fingerprint=hashlib.sha256(public).hexdigest(),
    )
