"""Persisted host-only Ed25519 keys never reach browser/gateway as secrets."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from arvectum_compliance.service.attestor_keys import load_attestor_identity
from arvectum_compliance.service.domain_proof import ProofError


def private_dir(tmp_path):
    path = tmp_path / "private"
    path.mkdir(mode=0o700)
    return path


def test_init_load_and_restart_preserve_identity(tmp_path):
    root = private_dir(tmp_path)
    first = load_attestor_identity(root, initialize=True)
    again = load_attestor_identity(root)
    assert first.public_fingerprint == again.public_fingerprint
    assert len(first.public_path.read_bytes()) == 32
    assert os.stat(root / "attestor-ed25519.key").st_mode & 0o777 == 0o600
    assert os.stat(root / "attestor-ed25519.pub").st_mode & 0o777 == 0o644
    assert first.private.private_bytes_raw() == again.private.private_bytes_raw()


def test_never_replace_signing_identity_implicitly(tmp_path):
    root = private_dir(tmp_path)
    first = load_attestor_identity(root, initialize=True)
    with pytest.raises(ProofError):
        load_attestor_identity(root, initialize=True)
    (root / "attestor-ed25519.pub").unlink()
    with pytest.raises(FileNotFoundError):
        load_attestor_identity(root)
    with pytest.raises(ProofError):
        load_attestor_identity(root, initialize=True)
    assert first.private.private_bytes_raw() == (root / "attestor-ed25519.key").read_bytes()


def test_mismatched_or_insecure_identity_rejected(tmp_path):
    root = private_dir(tmp_path)
    identity = load_attestor_identity(root, initialize=True)
    identity.public_path.write_bytes(b"x" * 32)
    with pytest.raises(ProofError, match="does not match"):
        load_attestor_identity(root)
    identity.public_path.write_bytes(identity.private.public_key().public_bytes_raw())
    os.chmod(root / "attestor-ed25519.key", 0o644)
    with pytest.raises(ProofError, match="permissions"):
        load_attestor_identity(root)


def test_directory_permissions_and_symlink_refused(tmp_path):
    root = private_dir(tmp_path)
    load_attestor_identity(root, initialize=True)
    os.chmod(root, 0o755)
    with pytest.raises(ProofError):
        load_attestor_identity(root)
    os.chmod(root, 0o700)
    link = tmp_path / "alias"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(ProofError):
        load_attestor_identity(link)


def test_parallel_initialization_wins_only_once(tmp_path):
    root = private_dir(tmp_path)
    def attempt(_):
        try:
            return load_attestor_identity(root, initialize=True).public_fingerprint
        except (ProofError, FileExistsError):
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        fingerprints = list(pool.map(attempt, range(12)))
    assert len([v for v in fingerprints if v]) == 1
    assert load_attestor_identity(root).public_fingerprint in fingerprints
