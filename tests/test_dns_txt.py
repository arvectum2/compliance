from __future__ import annotations

import pytest

from arvectum_compliance.service.dns_txt import lookup_ownership_txt
from arvectum_compliance.service.domain_proof import ProofError


class Answer:
    def __init__(self, *parts):
        self.strings = parts


class Resolver:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def resolve(self, name, kind, *, lifetime):
        self.calls.append((name, kind, lifetime))
        return self.answers


def test_dns_txt_segments_joined_without_shell_and_normalized():
    resolver = Resolver([Answer(b"arvectum-compliance-v1=", b"token")])
    assert lookup_ownership_txt(
        "_arvectum-compliance.EXAMPLE.COM", resolver=resolver,
    ) == ["arvectum-compliance-v1=token"]
    assert resolver.calls == [("_arvectum-compliance.example.com", "TXT", 3.0)]


@pytest.mark.parametrize("name", [
    "example.com", "_arvectum-compliance.127.1",
    "_arvectum-compliance.127.0.0.1",
    "_arvectum-compliance.example.com/../../private",
    "_arvectum-compliance.localhost",
])
def test_invalid_dns_location_is_never_queried(name):
    resolver = Resolver([])
    with pytest.raises(ProofError):
        lookup_ownership_txt(name, resolver=resolver)
    assert resolver.calls == []


def test_dns_failure_fails_closed_with_generic_error():
    class Failure:
        def resolve(self, *args, **kwargs):
            raise RuntimeError("private infrastructure SECRET_CANARY")
    with pytest.raises(ProofError, match="failed or timed out") as err:
        lookup_ownership_txt("_arvectum-compliance.example.com", resolver=Failure())
    assert "SECRET_CANARY" not in str(err.value)


def test_oversized_txt_refused():
    with pytest.raises(ProofError):
        lookup_ownership_txt(
            "_arvectum-compliance.example.com",
            resolver=Resolver([Answer(b"A" * 513)]),
        )
