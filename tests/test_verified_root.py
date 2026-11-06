"""Authenticated one-shot root probe: offline service and signed worker tests."""
from __future__ import annotations

import base64
import io
import json
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from arvectum_compliance.adapters.pinned_http import PinnedResponse
from arvectum_compliance.service import egress_worker, verified_root
from arvectum_compliance.service.attested_gateway import AttestedGatewaySession
from arvectum_compliance.service.attested_ipc import HostAttestor
from arvectum_compliance.service.attestor_keys import load_attestor_identity
from arvectum_compliance.service.authorization import GrantIssuer
from arvectum_compliance.service.domain_proof import ProofError
from arvectum_compliance.service.sqlite_proof import SqliteOwnershipRegistry
from arvectum_compliance.service.tenant_auth import TenantAuth
from arvectum_compliance.service.verified_jobs import VerifiedScanService

S = frozenset({"domain:verify", "scan:create", "domain:revoke"})


def setup(tmp_path):
    root = tmp_path / "keys"
    root.mkdir(mode=0o700)
    identity = load_attestor_identity(root, initialize=True)
    auth = TenantAuth(root / "auth.db")
    proofs = SqliteOwnershipRegistry(root / "proofs.db")
    issuer = GrantIssuer(proofs, b"S" * 32)
    issued = []
    service = VerifiedScanService(
        auth, proofs, issuer, dns_lookup=lambda _: issued.copy(),
    )
    token = auth.issue("tenant_A", scopes=S)
    return root, identity, service, token, issued


def test_verified_root_rejects_missing_real_proof_before_spawning(tmp_path, monkeypatch):
    _root, identity, service, token, _issued = setup(tmp_path)
    called = Mock()
    monkeypatch.setattr(verified_root.subprocess, "Popen", called)
    with pytest.raises(ProofError):
        verified_root.run_verified_root(
            service, identity, token, "unknown", "job_1",
        )
    called.assert_not_called()


def test_verified_root_rejects_expired_or_revoked_proof_before_spawning(
    tmp_path, monkeypatch,
):
    _root, identity, service, token, issued = setup(tmp_path)
    pending = service.issue_challenge(token, "example.com")
    issued.append(pending.record_value)
    proof = service.confirm_challenge(token, pending.id)
    service.revoke_domain(token, proof.id)
    called = Mock()
    monkeypatch.setattr(verified_root.subprocess, "Popen", called)
    with pytest.raises(ProofError):
        verified_root.run_verified_root(service, identity, token, proof.id, "job_1")
    called.assert_not_called()


def test_signed_verified_worker_gets_exact_root_only(tmp_path, monkeypatch):
    _root, identity, service, token, issued = setup(tmp_path)
    pending = service.issue_challenge(token, "example.com")
    issued.append(pending.record_value)
    proof = service.confirm_challenge(token, pending.id)
    grant = service.authorize_scan(token, proof.id, "job_1")
    signer = HostAttestor(service.issuer, identity.private)
    lease = signer.lease(grant)
    permit = signer.permit(
        grant, lease, sequence=1,
        url="https://example.com/", resource_type="document",
    )
    incoming = [
        {"kind": "lease", "lease": asdict(lease)},
        {
            "kind": "fetch", "id": 1, "url": "https://example.com/",
            "method": "GET", "resource_type": "document", "permit": asdict(permit),
        },
    ]
    body = ("\n".join(json.dumps(item) for item in incoming) + "\n").encode()
    output = io.StringIO()
    monkeypatch.setattr(egress_worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(body)))
    monkeypatch.setattr(egress_worker.sys, "stdout", output)
    monkeypatch.setattr(egress_worker.os, "geteuid", lambda: 65532)
    monkeypatch.setattr(
        egress_worker, "_read_attested_public_key", lambda: identity.private.public_key(),
    )
    fetcher = Mock(return_value=PinnedResponse(200, "text/html", b"<html>test</html>"))
    monkeypatch.setattr(
        egress_worker, "AttestedGatewaySession",
        lambda v, signed_lease: AttestedGatewaySession(v, signed_lease, fetcher=fetcher),
    )
    assert egress_worker.serve_attested_verified() == 0
    assert fetcher.call_count == 1
    assert fetcher.call_args.args == ("https://example.com/",)
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    assert lines[0] == {"kind": "ready"}
    assert base64.b64decode(lines[1]["body_b64"]) == b"<html>test</html>"


@pytest.mark.parametrize("override", [
    {"url": "https://example.com/admin"},
    {"url": "https://evil.example/"},
    {"resource_type": "stylesheet"},
    {"method": "POST"},
    {"id": 2},
])
def test_verified_worker_refuses_changed_target_before_fetch(tmp_path, monkeypatch, override):
    _root, identity, service, token, issued = setup(tmp_path)
    pending = service.issue_challenge(token, "example.com")
    issued.append(pending.record_value)
    proof = service.confirm_challenge(token, pending.id)
    grant = service.authorize_scan(token, proof.id, "job_1")
    signer = HostAttestor(service.issuer, identity.private)
    lease = signer.lease(grant)
    permit = signer.permit(
        grant, lease, sequence=1,
        url="https://example.com/", resource_type="document",
    )
    altered = {
        "kind": "fetch", "id": 1, "url": "https://example.com/",
        "method": "GET", "resource_type": "document", "permit": asdict(permit),
    }
    altered.update(override)
    body = (json.dumps({"kind": "lease", "lease": asdict(lease)}) +
            "\n" + json.dumps(altered) + "\n").encode()
    monkeypatch.setattr(egress_worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(body)))
    monkeypatch.setattr(egress_worker.sys, "stdout", io.StringIO())
    monkeypatch.setattr(egress_worker.os, "geteuid", lambda: 65532)
    monkeypatch.setattr(
        egress_worker, "_read_attested_public_key", lambda: identity.private.public_key(),
    )
    fetcher = Mock()
    monkeypatch.setattr(
        egress_worker, "AttestedGatewaySession",
        lambda v, signed_lease: AttestedGatewaySession(v, signed_lease, fetcher=fetcher),
    )
    assert egress_worker.serve_attested_verified() == 2
    fetcher.assert_not_called()


def test_host_broker_returns_only_hash_and_bytes(tmp_path, monkeypatch):
    import hashlib
    import os

    from arvectum_compliance.service import verified_jobs

    _root, identity, test_service, token, issued = setup(tmp_path)
    # Simulate the trusted *default* DoH path. No real network in unit tests.
    monkeypatch.setattr(
        verified_jobs, "lookup_doh_quorum_txt", lambda _name: issued.copy(),
    )
    service = VerifiedScanService(
        test_service.auth, test_service.proofs, test_service.issuer,
    )
    pending = service.issue_challenge(token, "example.com")
    issued.append(pending.record_value)
    proof = service.confirm_challenge(token, pending.id)

    runner = tmp_path / "fake-gateway"
    runner.write_text(
        "#!/usr/bin/env python3\n"
        "import base64,json,sys\n"
        "print('FIREWALL_APPLIED',flush=True)\n"
        "lease=json.loads(sys.stdin.readline())\n"
        "assert lease['kind']=='lease' and lease['lease']['hostname']=='example.com'\n"
        "print('{\"kind\":\"ready\"}',flush=True)\n"
        "req=json.loads(sys.stdin.readline())\n"
        "assert req['url']=='https://example.com/'\n"
        "assert req['method']=='GET' and req['resource_type']=='document'\n"
        "print(json.dumps({'kind':'reply','id':1,'allowed':True,'status':200,"
        "'content_type':'text/html','body_b64':"
        "base64.b64encode(b'<html>ok</html>').decode()}),flush=True)\n",
    )
    os.chmod(runner, 0o700)
    result = verified_root.run_verified_root(
        service, identity, token, proof.id, "job_1", runner=runner,
    )
    assert result == {
        "hostname": "example.com",
        "http_status": 200,
        "html_bytes": len(b"<html>ok</html>"),
        "sha256": hashlib.sha256(b"<html>ok</html>").hexdigest(),
        "job_id": "job_1",
        "policy": "gateway-v2",
        "domain_verified": True,
    }
    assert "body" not in result


def test_offline_test_dns_proof_must_never_launch_verified_gateway(tmp_path, monkeypatch):
    _root, identity, service, token, issued = setup(tmp_path)
    pending = service.issue_challenge(token, "example.com")
    issued.append(pending.record_value)
    proof = service.confirm_challenge(token, pending.id)
    called = Mock()
    monkeypatch.setattr(verified_root.subprocess, "Popen", called)
    with pytest.raises(ProofError, match="Real DNS ownership proof"):
        verified_root.run_verified_root(service, identity, token, proof.id, "job_1")
    called.assert_not_called()
