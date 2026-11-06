"""Opt-in Linux network-namespace firewall test; NOT a production launch gate."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    os.environ.get("COMPLIANCE_FIREWALL_E2E") != "1",
    reason="Requires explicit temporary nftables-probe Docker container",
)


def test_kernel_denies_local_sockets_even_when_app_checks_are_bypassed():
    completed = subprocess.run(
        [str(ROOT / "scripts/run-egress-kernel-probe.sh")],
        capture_output=True, text=True, timeout=50, check=True,
    )
    lines = completed.stdout.splitlines()
    assert "FIREWALL_APPLIED" in lines
    report = json.loads(lines[-1])
    assert report == {
        "uid": 65532,
        "caps_zero": True,
        "loopback_listener": "unreachable",
        "bridge_listener": "unreachable",
        "firewall_unmodifiable": True,
    }


@pytest.mark.parametrize(
    ("args", "exit_code", "message"),
    [
        ([], 25, "LOOPBACK_443_REACHABLE"),
        (["--bridge"], 26, "PRIVATE_BRIDGE_443_REACHABLE"),
    ],
)
def test_negative_controls_prove_firewall_changes_kernel_behavior(
    args, exit_code, message,
):
    """Without nft, the exact same port 443 listener must be reachable."""
    result = subprocess.run(
        [str(ROOT / "scripts/run-egress-kernel-negative-control.sh"), *args],
        capture_output=True, text=True, timeout=25,
    )
    assert result.returncode == exit_code
    assert message in result.stderr


def test_ipv6_loopback_is_blocked_by_kernel_not_app_code():
    protected = subprocess.run(
        [str(ROOT / "scripts/run-egress-kernel-ipv6.sh")],
        capture_output=True, text=True, timeout=35, check=True,
    )
    assert "FIREWALL_APPLIED" in protected.stdout.splitlines()
    assert json.loads(protected.stdout.splitlines()[-1]) == {
        "ipv6_loopback": "unreachable", "uid": 65532, "caps_zero": True,
    }


def test_ipv6_negative_control_connects_without_firewall():
    control = subprocess.run(
        [str(ROOT / "scripts/run-egress-kernel-negative-control.sh"), "--ipv6"],
        capture_output=True, text=True, timeout=35,
    )
    assert control.returncode == 35
    assert "IPV6_LOOPBACK_443_REACHABLE" in control.stderr
