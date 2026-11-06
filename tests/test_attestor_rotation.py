"""Local key generation rotation and in-flight verified request safety."""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from arvectum_compliance.service.attestor_keys import load_attestor_identity
from arvectum_compliance.service.attestor_rotation import (
    attestor_scan_guard,
    rotate_attestor_identity,
)
from arvectum_compliance.service.domain_proof import ProofError


def state(tmp_path: Path) -> Path:
    root = tmp_path / "keys"
    root.mkdir(mode=0o700)
    return root


def test_rotation_is_atomic_and_persists_new_identity(tmp_path):
    root = state(tmp_path)
    old = load_attestor_identity(root, initialize=True)
    old_pub = old.private.public_key().public_bytes_raw()
    rotated = rotate_attestor_identity(root)
    assert rotated.generation != "legacy"
    assert rotated.public_fingerprint != old.public_fingerprint
    assert rotated.private.public_key().public_bytes_raw() != old_pub
    assert not (root / "attestor-ed25519.key").exists()
    assert not (root / "attestor-ed25519.pub").exists()
    assert (root / "attestor-active.json").stat().st_mode & 0o777 == 0o600
    assert load_attestor_identity(root).public_fingerprint == rotated.public_fingerprint
    second = rotate_attestor_identity(root)
    assert second.generation not in ("legacy", rotated.generation)
    assert load_attestor_identity(root).generation == second.generation
    assert not (root / f"attestor-g-{rotated.generation}.key").exists()


def test_rotation_refused_while_verified_job_holds_shared_lock(tmp_path):
    root = state(tmp_path)
    old = load_attestor_identity(root, initialize=True)
    with attestor_scan_guard(old):
        with pytest.raises(ProofError, match="job active"):
            rotate_attestor_identity(root)
    current = rotate_attestor_identity(root)
    assert current.public_fingerprint != old.public_fingerprint
    with pytest.raises(ProofError, match="rotated since"):
        with attestor_scan_guard(old):
            pass


def test_new_identity_cannot_verify_old_attestation(tmp_path):
    from cryptography.exceptions import InvalidSignature

    root = state(tmp_path)
    old = load_attestor_identity(root, initialize=True)
    message = b"one exact owner-approved job"
    signature = old.private.sign(message)
    new = rotate_attestor_identity(root)
    with pytest.raises(InvalidSignature):
        new.private.public_key().verify(signature, message)


def test_tampered_or_world_readable_manifest_refused(tmp_path):
    root = state(tmp_path)
    load_attestor_identity(root, initialize=True)
    active = rotate_attestor_identity(root)
    marker = root / "attestor-active.json"
    os.chmod(marker, 0o644)
    with pytest.raises(ProofError, match="manifest permissions"):
        load_attestor_identity(root)
    os.chmod(marker, 0o600)
    payload = json.loads(marker.read_text())
    payload["fingerprint"] = "0" * 64
    marker.write_text(json.dumps(payload))
    with pytest.raises(ProofError, match="mismatch"):
        load_attestor_identity(root)
    payload["fingerprint"] = active.public_fingerprint
    marker.write_text(json.dumps(payload))
    assert load_attestor_identity(root).generation == active.generation


def test_incomplete_rotation_requires_explicit_recovery(tmp_path, monkeypatch):
    root = state(tmp_path)
    old = load_attestor_identity(root, initialize=True)

    def fail_atomic_swap(*_args, **_kwargs):
        raise OSError("injected power-loss-like failure")

    monkeypatch.setattr(
        "arvectum_compliance.service.attestor_rotation.os.replace",
        fail_atomic_swap,
    )
    with pytest.raises(OSError, match="injected"):
        rotate_attestor_identity(root)
    assert (root / "attestor-ed25519.key").exists()
    assert old.private.private_bytes_raw() == (root / "attestor-ed25519.key").read_bytes()
    with pytest.raises(ProofError, match="Incomplete rotation"):
        load_attestor_identity(root)


def test_missing_manifest_cannot_restore_retired_legacy_pair(tmp_path):
    root = state(tmp_path)
    load_attestor_identity(root, initialize=True)
    rotate_attestor_identity(root)
    (root / "attestor-active.json").unlink()
    with pytest.raises(ProofError, match="Incomplete rotation"):
        load_attestor_identity(root)


def test_operator_requires_explicit_rotation_confirmation(tmp_path, capsys):
    from arvectum_compliance.service.operator_cli import main

    root = state(tmp_path)
    args = ["--state-dir", str(root)]
    assert main([*args, "attestor-init"]) == 0
    baseline = load_attestor_identity(root)
    assert main([*args, "attestor-rotate"]) == 2
    assert load_attestor_identity(root).public_fingerprint == baseline.public_fingerprint
    assert main([*args, "attestor-rotate", "--confirm-rotation"]) == 0
    assert load_attestor_identity(root).public_fingerprint != baseline.public_fingerprint


def test_verified_root_refuses_stale_key_before_starting_docker(tmp_path, monkeypatch):
    from arvectum_compliance.service import verified_root

    root = state(tmp_path)
    first = load_attestor_identity(root, initialize=True)
    rotate_attestor_identity(root)
    called = Mock()
    monkeypatch.setattr(verified_root.subprocess, "Popen", called)
    with pytest.raises(ProofError, match="rotated since"):
        verified_root.run_verified_root(
            Mock(), first, "acp_fake", "not-a-proof", "job_1",
        )
    called.assert_not_called()


def test_operator_can_recover_uncommitted_rotation_but_never_promotes_orphan(
    tmp_path, monkeypatch,
):
    from arvectum_compliance.service.attestor_rotation import recover_attestor_state

    root = state(tmp_path)
    old = load_attestor_identity(root, initialize=True)
    with monkeypatch.context() as patch:
        patch.setattr(
            "arvectum_compliance.service.attestor_rotation.os.replace",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("power loss")),
        )
        with pytest.raises(OSError, match="power loss"):
            rotate_attestor_identity(root)
    with pytest.raises(ProofError, match="Incomplete rotation"):
        load_attestor_identity(root)
    restored, discarded = recover_attestor_state(root)
    assert discarded == 3
    assert restored.public_fingerprint == old.public_fingerprint
    assert restored.generation == "legacy"
    assert rotate_attestor_identity(root).generation != "legacy"


def test_recovery_rejects_missing_trusted_identity_and_does_not_promote_orphan(tmp_path):
    from arvectum_compliance.service.attestor_rotation import recover_attestor_state

    root = state(tmp_path)
    new_key = root / ("attestor-g-" + "e" * 32 + ".key")
    new_key.write_bytes(b"K" * 32)
    new_key.chmod(0o600)
    with pytest.raises(FileNotFoundError):
        recover_attestor_state(root)
    assert new_key.exists()


def test_recovery_cleans_retired_legacy_after_atomic_manifest_commit(tmp_path):
    from arvectum_compliance.service.attestor_rotation import recover_attestor_state

    root = state(tmp_path)
    old = load_attestor_identity(root, initialize=True)
    active = rotate_attestor_identity(root)
    retired = root / "attestor-ed25519.key"
    retired.write_bytes(old.private.private_bytes_raw())
    retired.chmod(0o600)
    recovered, discarded = recover_attestor_state(root)
    assert discarded == 1
    assert recovered.public_fingerprint == active.public_fingerprint
    assert not retired.exists()


def test_recovery_requires_acknowledgement_and_cannot_run_during_scan(tmp_path, capsys):
    from arvectum_compliance.service.operator_cli import main

    root = state(tmp_path)
    args = ["--state-dir", str(root)]
    assert main([*args, "attestor-init"]) == 0
    identity = load_attestor_identity(root)
    assert main([*args, "attestor-recover"]) == 2
    with attestor_scan_guard(identity):
        assert main([*args, "attestor-recover", "--confirm-recovery"]) == 2
    assert main([*args, "attestor-recover", "--confirm-recovery"]) == 0
    assert load_attestor_identity(root).public_fingerprint == identity.public_fingerprint


def test_rotation_refuses_leftover_retired_key_until_explicit_recovery(tmp_path):
    from arvectum_compliance.service.attestor_rotation import recover_attestor_state

    root = state(tmp_path)
    old = load_attestor_identity(root, initialize=True)
    current = rotate_attestor_identity(root)
    retired_path = root / "attestor-ed25519.key"
    retired_path.write_bytes(old.private.private_bytes_raw())
    retired_path.chmod(0o600)
    with pytest.raises(ProofError, match="Retired legacy"):
        rotate_attestor_identity(root)
    recovered, removed = recover_attestor_state(root)
    assert removed == 1
    assert recovered.public_fingerprint == current.public_fingerprint
    assert rotate_attestor_identity(root).public_fingerprint != current.public_fingerprint
