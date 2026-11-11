"""Isolated signed browser->gateway E2E using ONLY fake DNS and local fixtures.

Host signs fresh per-request permits AFTER durable proof checks. The gateway
holds only an Ed25519 public key and independently validates every permit.
No production site, DNS record or credential is touched in this harness.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arvectum_compliance.adapters.browser_fixture import parse_fixture_json
from arvectum_compliance.adapters.isolated_bridge import _BoundedLines, _stop
from arvectum_compliance.service.attested_ipc import HostAttestor
from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.sqlite_proof import SqliteOwnershipRegistry
from arvectum_compliance.service.tenant_auth import TenantAuth
from arvectum_compliance.service.verified_jobs import VerifiedScanService

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = frozenset(("consent.html", "attack.html", "inconclusive.html", "security.html"))


def run_attested_fixture(
    fixture: str, *, revoke_after: int | None = None,
    tamper_lease: bool = False, tamper_permit: bool = False,
    timeout_s: int = 65,
):
    if fixture not in FIXTURES or not 15 <= timeout_s <= 100:
        raise ValueError("Only bounded offline fixture scans are accepted")
    deadline = time.monotonic() + timeout_s
    with tempfile.TemporaryDirectory(prefix="arvectum-verified-fixture-") as root:
        state = Path(root)
        state.chmod(0o700)
        auth = TenantAuth(state / "auth.db")
        proofs = SqliteOwnershipRegistry(state / "proofs.db")
        issuer = GrantIssuer(proofs, secrets.token_bytes(32))
        token = auth.issue(
            "test_tenant", scopes=frozenset({"domain:verify", "scan:create"}),
            ttl=300,
        )
        published = []

        def mock_dns(_name: str) -> list[str]:
            # EXPLICIT OFFLINE MOCK: never claim real DNS verification.
            return published.copy()

        service = VerifiedScanService(auth, proofs, issuer, dns_lookup=mock_dns)
        ch = service.issue_challenge(token, "compliance-fixture.invalid")
        published.append(ch.record_value)
        proof = service.confirm_challenge(token, ch.id)
        grant = service.authorize_scan(token, proof.id, "test_job")
        key = Ed25519PrivateKey.generate()
        pub_path = state / "attestor.pub"
        pub_path.write_bytes(key.public_key().public_bytes_raw())
        pub_path.chmod(0o444)
        attestor = HostAttestor(issuer, key)
        lease = attestor.lease(grant)
        lease_wire = asdict(lease)
        if tamper_lease:
            lease_wire["hostname"] = "evil.example"
        env = {**os.environ, "COMPLIANCE_ATTEST_PUBLIC_KEY_FILE": str(pub_path)}
        gateway = subprocess.Popen(
            [str(ROOT / "scripts/run-egress-attested-fixture.sh"), fixture],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0,
        )
        gw_lines = _BoundedLines(gateway)
        browser = None
        br_lines = None
        try:
            if gw_lines.next(deadline, 100) != b"FIREWALL_APPLIED\n":
                raise RuntimeError("Gateway firewall failed before authorization")
            assert gateway.stdin is not None
            gateway.stdin.write(
                (json.dumps({"kind": "lease", "lease": lease_wire}) + "\n").encode()
            )
            gateway.stdin.flush()
            if gw_lines.next(deadline, 100) != b'{"kind":"ready"}\n':
                raise RuntimeError("Gateway did not verify signed lease")
            browser = subprocess.Popen(
                [str(ROOT / "scripts/run-browser-bridge-fixture.sh"), fixture],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0,
            )
            br_lines = _BoundedLines(browser)
            requests = 0
            approved = 0
            while time.monotonic() < deadline:
                msg = json.loads(br_lines.next(deadline, 80_000))
                if not isinstance(msg, dict):
                    raise ValueError("Bad browser request envelope")
                if msg.get("kind") == "fetch":
                    requests += 1
                    if (
                        requests > 120
                        or set(msg) != {"kind", "id", "url", "method", "resource_type"}
                        or type(msg["id"]) is not int or msg["id"] != requests
                    ):
                        raise ValueError("Invalid or replayed browser request")
                    reply = {"kind": "reply", "id": requests, "allowed": False}
                    try:
                        if msg["method"] != "GET":
                            raise ValueError("Mutation denied")
                        permit = attestor.permit(
                            grant, lease, sequence=approved + 1,
                            url=msg["url"], resource_type=msg["resource_type"],
                        )
                    except (ValueError, TypeError):
                        pass  # Deny locally, never forward to gateway.
                    else:
                        approved += 1
                        if revoke_after == approved:
                            proofs.revoke("test_tenant", proof.id)
                        permit_wire = asdict(permit)
                        if tamper_permit:
                            permit_wire["resource_type"] = "script"
                        request = {
                            **msg, "id": approved, "permit": permit_wire,
                        }
                        gateway.stdin.write((json.dumps(request) + "\n").encode())
                        gateway.stdin.flush()
                        gateway_reply = json.loads(gw_lines.next(deadline, 1_600_000))
                        if (
                            not isinstance(gateway_reply, dict)
                            or gateway_reply.get("kind") != "reply"
                            or gateway_reply.get("id") != approved
                        ):
                            raise ValueError("Invalid signed gateway response")
                        reply = {**gateway_reply, "id": requests}
                    assert browser.stdin is not None
                    browser.stdin.write((json.dumps(reply) + "\n").encode())
                    browser.stdin.flush()
                elif msg.get("kind") == "result":
                    if set(msg) != {"kind", "report"}:
                        raise ValueError("Invalid browser result envelope")
                    raw = msg["report"]
                    if raw.get("fixture") != fixture:
                        raise ValueError("Fixture mismatch")
                    report = parse_fixture_json(json.dumps(raw))
                    return report, approved
                else:
                    raise RuntimeError("Attested browser failed closed")
            raise TimeoutError("Attested browser timed out")
        finally:
            if br_lines is not None:
                br_lines.close()
            gw_lines.close()
            if browser is not None:
                _stop(browser)
            _stop(gateway)
