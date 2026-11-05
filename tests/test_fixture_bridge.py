"""Strict gateway IPC unit tests; no browser or DNS required."""
from __future__ import annotations

import json

import pytest

from arvectum_compliance.adapters.fixture_bridge import (
    ORIGIN,
    _gateway_for_fixture,
    _gateway_reply,
    run_fixture_bridge,
)


def request(url=ORIGIN, *, method="GET", resource="document", id=1):
    return {
        "kind": "fetch", "id": id, "url": url,
        "method": method, "resource_type": resource,
    }


def test_fixture_gateway_allows_exact_owned_origin_without_network():
    gateway = _gateway_for_fixture("consent.html")
    reply = _gateway_reply(request(), gateway)
    assert reply["kind"] == "reply"
    assert reply["id"] == 1
    assert reply["allowed"] is True
    assert reply["status"] == 200
    assert "body_b64" in reply
    assert gateway.usage[0] == 1


@pytest.mark.parametrize("url", [
    "https://attacker.invalid/secret", "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "https://compliance-fixture.invalid.evil.org/",
    "https://user:pass@compliance-fixture.invalid/",
    "https://compliance-fixture.invalid:8443/",
])
def test_gateway_denies_out_of_scope_before_transport(url):
    gateway = _gateway_for_fixture("attack.html")
    result = _gateway_reply(request(url), gateway)
    assert result == {"kind": "reply", "id": 1, "allowed": False}
    assert gateway.usage == (0, 0)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "HEAD"])
def test_gateway_never_forwards_mutation_or_unapproved_method(method):
    gateway = _gateway_for_fixture("attack.html")
    assert _gateway_reply(request(method=method), gateway)["allowed"] is False
    assert gateway.usage == (0, 0)


def test_unsupported_resource_type_rejected():
    gateway = _gateway_for_fixture("consent.html")
    assert _gateway_reply(request(resource="websocket"), gateway)["allowed"] is False
    assert gateway.usage == (0, 0)


@pytest.mark.parametrize("bad", [
    {"kind": "fetch", "id": 1, "url": ORIGIN},
    {"kind": "fetch", "id": 1, "url": ORIGIN, "method": "GET",
     "resource_type": "document", "header": {"Cookie": "CANARY"}},
    request(id=True),
    request(id=0),
    request(id=121),
])
def test_reject_malformed_ipc_request(bad):
    with pytest.raises(ValueError):
        _gateway_reply(bad, _gateway_for_fixture("consent.html"))


def test_message_output_is_not_a_browser_data_dump():
    gateway = _gateway_for_fixture("attack.html")
    denied = _gateway_reply(request("https://evil.example/secret?token=SECRET_CANARY"), gateway)
    assert "SECRET_CANARY" not in json.dumps(denied)
    assert "secret" not in json.dumps(denied)


def test_no_arbitrary_filename_or_command_path():
    with pytest.raises(ValueError):
        run_fixture_bridge("../.env")
    with pytest.raises(ValueError):
        run_fixture_bridge("https://arvectum.com/")
