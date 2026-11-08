from __future__ import annotations

import json
import os

from arvectum_compliance.service import operator_cli, verified_jobs
from arvectum_compliance.service.domain_proof import ProofError


def call(capsys, state, *args):
    result = operator_cli.main(["--state-dir", str(state), *args])
    out, err = capsys.readouterr()
    return result, out, err


def test_full_internal_operator_flow_uses_local_files_not_stdout_secrets(
    tmp_path, capsys, monkeypatch,
):
    state = tmp_path / "private"
    rc, out, err = call(capsys, state, "provision", "--tenant", "org_A")
    assert rc == 0 and not err, (
        rc, out, err, list(state.iterdir()) if state.exists() else "absent",
    )
    token_path = state / "tenant-org_A.token"
    token = token_path.read_text()
    assert token.startswith("acp_")
    assert token not in out
    assert os.stat(token_path).st_mode & 0o077 == 0
    assert os.stat(state).st_mode & 0o077 == 0
    assert token.encode() not in (state / "access.db").read_bytes()

    rc, out, _ = call(
        capsys, state, "challenge", "--token-file", str(token_path),
        "--host", "example.com",
    )
    assert rc == 0
    challenge = json.loads(out)
    assert challenge["record_name"] == "_arvectum-compliance.example.com"
    monkeypatch.setattr(
        verified_jobs, "lookup_doh_quorum_txt",
        lambda _: [challenge["record_value"]],
    )
    rc, out, _ = call(
        capsys, state, "confirm", "--token-file", str(token_path),
        "--proof-id", challenge["id"],
    )
    assert rc == 0
    proof = json.loads(out)
    assert proof["hostname"] == "example.com"
    grant_path = state / "job-one.json"
    rc, out, _ = call(
        capsys, state, "grant", "--token-file", str(token_path),
        "--proof-id", proof["id"], "--job-id", "job_one",
        "--output", str(grant_path),
    )
    assert rc == 0
    assert str(grant_path) in out
    grant = json.loads(grant_path.read_text())
    assert grant["hostname"] == "example.com"
    assert os.stat(grant_path).st_mode & 0o077 == 0
    rc, _, _ = call(
        capsys, state, "revoke", "--token-file", str(token_path),
        "--proof-id", proof["id"],
    )
    assert rc == 0
    another = state / "job-two.json"
    rc, out, err = call(
        capsys, state, "grant", "--token-file", str(token_path),
        "--proof-id", proof["id"], "--job-id", "job_two",
        "--output", str(another),
    )
    assert rc == 2 and not out and not another.exists()
    assert "ERROR" in err and token not in err


def test_absent_dns_fails_closed_without_writing_grants(tmp_path, capsys, monkeypatch):
    state = tmp_path / "private"
    rc, _, _ = call(capsys, state, "provision", "--tenant", "org_A")
    assert rc == 0
    token_path = state / "tenant-org_A.token"
    rc, out, _ = call(
        capsys, state, "challenge", "--token-file", str(token_path),
        "--host", "example.com",
    )
    challenge = json.loads(out)
    def no_dns(_):
        raise ProofError("No verified DNS record")
    monkeypatch.setattr(verified_jobs, "lookup_doh_quorum_txt", no_dns)
    rc, out, err = call(
        capsys, state, "confirm", "--token-file", str(token_path),
        "--proof-id", challenge["id"],
    )
    assert rc == 2 and not out and "ERROR" in err
    rc, _, _ = call(
        capsys, state, "grant", "--token-file", str(token_path),
        "--proof-id", challenge["id"], "--job-id", "no_proof",
        "--output", str(state / "not-granted.json"),
    )
    assert rc == 2
    assert not (state / "not-granted.json").exists()


def test_second_provision_or_world_readable_state_is_refused(tmp_path, capsys):
    state = tmp_path / "private"
    assert call(capsys, state, "provision", "--tenant", "org_A")[0] == 0
    assert call(capsys, state, "provision", "--tenant", "org_A")[0] == 2
    os.chmod(state, 0o755)
    assert call(capsys, state, "provision", "--tenant", "org_B")[0] == 2


def test_operator_attestor_init_info_and_no_overwrite(tmp_path, capsys):

    state = tmp_path / "private"
    setup_status = call(capsys, state, "provision", "--tenant", "org_A")
    assert setup_status[0] == 0, setup_status
    rc, out, _ = call(capsys, state, "attestor-init")
    assert rc == 0
    fingerprint = json.loads(out)["public_fingerprint"]
    assert len(fingerprint) == 64
    assert os.stat(state / "attestor-ed25519.key").st_mode & 0o777 == 0o600
    rc, out, _ = call(capsys, state, "attestor-info")
    assert rc == 0 and json.loads(out)["public_fingerprint"] == fingerprint
    assert call(capsys, state, "attestor-init")[0] == 2


def test_operator_verified_root_refuses_unknown_proof(tmp_path, capsys):
    state = tmp_path / "private"
    assert call(capsys, state, "provision", "--tenant", "org_A")[0] == 0
    assert call(capsys, state, "attestor-init")[0] == 0
    token_path = state / "tenant-org_A.token"
    rc, out, err = call(
        capsys, state, "verified-root",
        "--token-file", str(token_path),
        "--proof-id", "not_verified", "--job-id", "job_1",
    )
    assert rc == 2
    assert not out
    assert "ERROR" in err
    assert "acp_" not in err


def test_binary_signing_key_preserves_leading_trailing_whitespace(tmp_path, capsys, monkeypatch):
    """Random 256-bit HMAC keys are raw bytes and must NEVER be stripped."""
    from arvectum_compliance.service import operator_cli

    example_key = b"\n" + b"x" * 30 + b" "
    assert len(example_key) == 32
    monkeypatch.setattr(operator_cli.secrets, "token_bytes", lambda size: example_key)
    state = tmp_path / "private"
    rc, out, err = call(capsys, state, "provision", "--tenant", "org_A")
    assert rc == 0, (out, err)
    assert (state / "signing.key").read_bytes() == example_key
    assert operator_cli._read_secret(state / "signing.key") == example_key
    assert call(capsys, state, "attestor-init")[0] == 0


def test_ledger_audit_cli_is_read_only_and_fails_closed(tmp_path, capsys):
    from arvectum_compliance.service.job_ledger import JobLedger

    state = tmp_path / "private"
    state.mkdir(mode=0o700)
    rc, out, err = call(capsys, state, "ledger-audit")
    assert rc == 2 and not out and "ERROR" in err
    assert list(state.iterdir()) == []

    ledger = JobLedger(state / "jobs.db")
    before = (state / "jobs.db").read_bytes()
    rc, out, err = call(capsys, state, "ledger-audit")
    assert rc == 0 and not err and json.loads(out)["gate"] == "PASS"
    assert (state / "jobs.db").read_bytes() == before
    assert not (state / "signing.key").exists()

    with ledger._db() as db:
        db.execute("INSERT INTO maintenance_cursor(name,created,tenant,job) "
                   "VALUES ('invalid',1,'org_A','job_1')")
    rc, out, err = call(capsys, state, "ledger-audit")
    assert rc == 3 and not err and json.loads(out)["gate"] == "NO-GO"
    rc, out, err = call(capsys, state, "ledger-audit", "--limit", "0")
    assert rc == 2 and not out and "ERROR" in err


def test_ledger_audit_cli_corrupt_sqlite_fails_closed(tmp_path, capsys):
    state = tmp_path / "private"
    state.mkdir(mode=0o700)
    database = state / "jobs.db"
    database.write_bytes(b"not a sqlite database")
    database.chmod(0o600)
    before = database.read_bytes()
    rc, out, err = call(capsys, state, "ledger-audit")
    assert rc == 2 and not out
    assert "ERROR: DatabaseError" in err
    assert str(database) not in err
    assert database.read_bytes() == before
    assert list(state.iterdir()) == [database]
