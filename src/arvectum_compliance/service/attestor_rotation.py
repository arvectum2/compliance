"""Explicit offline Ed25519 rotation with an atomic active-key manifest.

Rotations are serialized by flock. The verified-root runner acquires a
shared lock for its entire job. This is LOCAL/SINGLE-HOST only; KMS/HSM and
cross-machine revocation remain production blockers.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .domain_proof import ProofError

_MANIFEST = "attestor-active.json"
_LOCK = "attestor-rotation.lock"
_GEN = re.compile(r"[0-9a-f]{32}\Z")


@contextmanager
def key_lock(root: Path, *, exclusive: bool, blocking: bool = True):
    from .attestor_keys import _secure_state_directory

    root = _secure_state_directory(root)
    path = root / _LOCK
    fd = os.open(
        path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    try:
        if (
            not stat.S_ISREG(os.fstat(fd).st_mode)
            or os.fstat(fd).st_mode & 0o777 != 0o600
        ):
            raise ProofError("Unsafe attestor rotation lock file")
        try:
            fcntl.flock(
                fd,
                (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                | (0 if blocking else fcntl.LOCK_NB),
            )
        except BlockingIOError as exc:
            raise ProofError("Attestor job active; rotation refused") from exc
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def find_orphaned_generation(root: Path) -> bool:
    return any(root.glob("attestor-g-*.key")) or any(root.glob("attestor-g-*.pub"))


def _manifest(root: Path) -> dict[str, str | int] | None:
    path = root / _MANIFEST
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink():
        raise ProofError("Key generation manifest cannot be a symlink")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o777 != 0o600:
            raise ProofError("Invalid key generation manifest permissions")
        if st.st_size < 2 or st.st_size > 512:
            raise ProofError("Invalid key generation manifest length")
        raw = os.read(fd, 513)
    finally:
        os.close(fd)
    try:
        manifest = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ProofError("Malformed key generation manifest") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "generation", "fingerprint"}
        or type(manifest["schema"]) is not int
        or manifest["schema"] != 1
        or not isinstance(manifest["generation"], str)
        or not _GEN.fullmatch(manifest["generation"])
        or not isinstance(manifest["fingerprint"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest["fingerprint"])
    ):
        raise ProofError("Invalid active signing key manifest")
    return manifest


def active_generation(root: Path):
    """Return current rotated identity, or None for legacy pre-rotation."""
    from .attestor_keys import AttestorIdentity, _read_regular

    data = _manifest(root)
    if data is None:
        return None
    gen = str(data["generation"])
    raw_private = _read_regular(root / f"attestor-g-{gen}.key", mode=0o600, size=32)
    raw_public = _read_regular(root / f"attestor-g-{gen}.pub", mode=0o644, size=32)
    private = Ed25519PrivateKey.from_private_bytes(raw_private)
    fp = hashlib.sha256(raw_public).hexdigest()
    if (
        fp != data["fingerprint"]
        or raw_public != private.public_key().public_bytes_raw()
    ):
        raise ProofError("Attestor active key pair or fingerprint mismatch")
    return AttestorIdentity(private, root / f"attestor-g-{gen}.pub", fp, root, gen)


@contextmanager
def attestor_scan_guard(identity):
    """Retain shared lock through every signed request and response check."""
    from .attestor_keys import load_attestor_identity

    with key_lock(identity.state_dir, exclusive=False):
        actual = load_attestor_identity(identity.state_dir)
        if (
            actual.public_fingerprint != identity.public_fingerprint
            or actual.generation != identity.generation
        ):
            raise ProofError("Attestor rotated since job identity was loaded")
        yield


def rotate_attestor_identity(state_dir: str | Path):
    """Activate new key atomically; refuse concurrent jobs and preserve no fallback."""
    from .attestor_keys import (
        _exclusive_private_file,
        _secure_state_directory,
        load_attestor_identity,
    )

    root = _secure_state_directory(Path(state_dir))
    with key_lock(root, exclusive=True, blocking=False):
        current = load_attestor_identity(root)
        if current.generation != "legacy":
            active_names = {
                f"attestor-g-{current.generation}.key",
                f"attestor-g-{current.generation}.pub",
            }
            if any(
                file.name not in active_names
                for file in root.glob("attestor-g-*")
            ) or any(root.glob(".attestor-*.tmp")):
                raise ProofError("Retired signing artifacts require explicit recovery")
            if (
                (root / "attestor-ed25519.key").exists()
                or (root / "attestor-ed25519.pub").exists()
            ):
                raise ProofError("Retired legacy signing seed requires recovery")
        generation = secrets.token_hex(16)
        candidate = Ed25519PrivateKey.generate()
        public = candidate.public_key().public_bytes_raw()
        next_private = root / f"attestor-g-{generation}.key"
        next_public = root / f"attestor-g-{generation}.pub"
        temp_manifest = root / f".attestor-{generation}.tmp"
        # If a crash occurs before manifest activation, the old active
        # identity cannot silently fall back while orphan files remain.
        _exclusive_private_file(next_private, candidate.private_bytes_raw(), 0o600)
        _exclusive_private_file(next_public, public, 0o644)
        body = json.dumps({
            "schema": 1, "generation": generation,
            "fingerprint": hashlib.sha256(public).hexdigest(),
        }, sort_keys=True).encode()
        _exclusive_private_file(temp_manifest, body, 0o600)
        os.replace(temp_manifest, root / _MANIFEST)
        directory_fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        # Retired private seed is no longer loaded after atomic activation.
        # Filesystem unlink is NOT guaranteed secure erasure.
        if current.generation == "legacy":
            retired = [root / "attestor-ed25519.key", root / "attestor-ed25519.pub"]
        else:
            retired = [
                root / f"attestor-g-{current.generation}.key",
                root / f"attestor-g-{current.generation}.pub",
            ]
        for path in retired:
            path.unlink()
        return load_attestor_identity(root)


def recover_attestor_state(state_dir: str | Path):
    """Explicit, locked recovery of uncommitted generations.

    Requires a cryptographically matching ACTIVE identity. Never recovers
    missing active keys or makes an orphan generation authoritative.
    """
    from .attestor_keys import _read_regular, _secure_state_directory, load_attestor_identity

    root = _secure_state_directory(Path(state_dir))
    with key_lock(root, exclusive=True, blocking=False):
        active = active_generation(root)
        if active is None:
            # Legacy active identity may coexist with orphan rotation files.
            private_bytes = _read_regular(
                root / "attestor-ed25519.key", mode=0o600, size=32,
            )
            public_bytes = _read_regular(
                root / "attestor-ed25519.pub", mode=0o644, size=32,
            )
            if Ed25519PrivateKey.from_private_bytes(
                private_bytes,
            ).public_key().public_bytes_raw() != public_bytes:
                raise ProofError("Legacy signing identity is not intact")
        allowed = re.compile(
            r"attestor-g-[0-9a-f]{32}\.(?:key|pub)|\.attestor-[0-9a-f]{32}\.tmp\Z",
        )
        discarded: list[Path] = []
        for path in root.iterdir():
            if not (path.name.startswith("attestor-g-") or path.name.startswith(".attestor-")):
                continue
            if not allowed.fullmatch(path.name):
                raise ProofError("Unexpected recovery artifact")
            if active is not None and path.name in {
                f"attestor-g-{active.generation}.key",
                f"attestor-g-{active.generation}.pub",
            }:
                continue
            if path.is_symlink() or not path.is_file():
                raise ProofError("Unsafe recovery artifact")
            expected_mode = 0o644 if path.suffix == ".pub" else 0o600
            if path.stat().st_mode & 0o777 != expected_mode:
                raise ProofError("Recovery artifact has unsafe file mode")
            discarded.append(path)
        if active is not None:
            # A crash after manifest activation may leave retired legacy
            # files, but they are not trusted as a fallback identity.
            discarded += [
                path for path in (
                    root / "attestor-ed25519.key",
                    root / "attestor-ed25519.pub",
                ) if path.exists() or path.is_symlink()
            ]
        for path in discarded:
            if path.is_symlink():
                raise ProofError("Symlinked retired identity refused")
        for path in discarded:
            path.unlink()
        directory_fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return load_attestor_identity(root), len(discarded)
