from __future__ import annotations

from unittest.mock import Mock

import pytest

from arvectum_compliance.adapters.pinned_http import PinnedResponse
from arvectum_compliance.service.egress_worker import handle_fetch


def message(url="https://compliance-fixture.invalid/", *, method="GET", id=1, kind="document"):
    return {"kind": "fetch", "id": id, "url": url, "method": method, "resource_type": kind}


def test_allow_exact_get_with_bounded_reply():
    gateway = Mock()
    gateway.get.return_value = PinnedResponse(200, "text/html", b"<html/>")
    reply = handle_fetch(message(), gateway, expected_id=1)
    assert reply["allowed"] is True
    gateway.get.assert_called_once_with("https://compliance-fixture.invalid/")


@pytest.mark.parametrize("bad", [
    message(method="POST"), message(kind="websocket"),
    message(method="DELETE"), message(kind="other"),
])
def test_mutations_and_unknown_resources_never_forwarded(bad):
    gateway = Mock()
    assert handle_fetch(bad, gateway, expected_id=1)["allowed"] is False
    gateway.get.assert_not_called()


def test_replay_and_malformed_denied():
    with pytest.raises(ValueError):
        handle_fetch(message(id=2), Mock(), expected_id=1)
    with pytest.raises(ValueError):
        handle_fetch({**message(), "cookie": "SECRET"}, Mock(), expected_id=1)


def test_denial_does_not_echo_sensitive_url():
    gateway = Mock()
    gateway.get.side_effect = ValueError("private query SECRET_CANARY")
    result = handle_fetch(message("https://evil.example/?token=SECRET"), gateway, expected_id=1)
    assert result == {"kind": "reply", "id": 1, "allowed": False}


def test_oversized_reply_rejected():
    gateway = Mock()
    gateway.get.return_value = PinnedResponse(200, "text/html", b"x" * 1_000_001)
    assert handle_fetch(message(), gateway, expected_id=1)["allowed"] is False



@pytest.mark.parametrize("bad", [
    message(url="https://evil.example/"),
    message(url="https://arvectum.com/contact"),
    message(url="http://arvectum.com/"),
    message(method="POST"),
    message(kind="stylesheet"),
    {**message(), "cookie": "CANARY"},
])
def test_internal_owned_mode_only_root_document_get(bad):
    from arvectum_compliance.service.egress_worker import _owned_document_only

    assert not _owned_document_only(bad)
    assert _owned_document_only(message(url="https://arvectum.com/"))
