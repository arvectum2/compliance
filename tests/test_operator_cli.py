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
    assert rc == 0 and not err
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
