"""No real DNS or HTTP: kernel-isolated verified worker refuses forged proof."""
from __future__ import annotations

import json
import os
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.skipif(
    os.environ.get("COMPLIANCE_DOCKER_E2E") != "1",
    reason="Opt-in real Linux nftables gateway image E2E only",
)


def test_verified_gateway_rejects_fake_or_unsigned_lease(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "public.bin"
    path.write_bytes(key.public_key().public_bytes_raw())
    env = {
        **os.environ,
        "COMPLIANCE_ATTEST_PUBLIC_KEY_FILE": str(path),
    }
    forged = {
        "kind": "lease",
        "lease": {
            "tenant_id": "attacker", "hostname": "example.com",
            "policy_version": "gateway-v2", "signature": "0" * 128,
        },
    }
    run = subprocess.run(
        ["scripts/run-egress-attested-verified.sh"],
        input=json.dumps(forged) + "\n",
        env=env, text=True, capture_output=True, timeout=30,
    )
    assert run.returncode != 0
    assert run.stdout.splitlines() == ["FIREWALL_APPLIED"]
    assert "example.com" not in run.stderr


def test_verified_gateway_fails_without_trusted_public_key():
    env = {key: value for key, value in os.environ.items()
           if key != "COMPLIANCE_ATTEST_PUBLIC_KEY_FILE"}
    run = subprocess.run(
        ["scripts/run-egress-attested-verified.sh"],
        env=env, input="", text=True, capture_output=True, timeout=10,
    )
    assert run.returncode != 0
    assert "Missing regular public key" in run.stderr
    assert "FIREWALL_APPLIED" not in run.stdout
