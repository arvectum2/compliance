from __future__ import annotations

from unittest.mock import Mock

import pytest

from arvectum_compliance.service.dns_txt import lookup_quorum_txt
from arvectum_compliance.service.domain_proof import ProofError

RECORD = "_arvectum-compliance.example.com"


class TextRecord:
    def __init__(self, value: str):
        self.strings = (value.encode("ascii"),)


class Resolver:
    def __init__(self, records, fail=False):
        self.records = records
        self.fail = fail
        self.calls = []

    def resolve(self, name, kind, *, lifetime):
        self.calls.append((name, kind, lifetime))
        if self.fail:
            raise TimeoutError("DNS request timed out")
        return [TextRecord(value) for value in self.records]


def test_independent_resolvers_return_identical_nonempty_answer():
    a = Resolver(["arvectum-compliance-v1=abc.xyz"])
    b = Resolver(["arvectum-compliance-v1=abc.xyz"])
    factory = Mock(side_effect=[a, b])
    assert lookup_quorum_txt(RECORD, resolver_factory=factory) == [
        "arvectum-compliance-v1=abc.xyz"
    ]
    assert factory.call_args_list[0].args == ("1.1.1.1",)
    assert factory.call_args_list[1].args == ("9.9.9.9",)
    assert a.calls == [(RECORD, "TXT", 3.0)]
    assert b.calls == [(RECORD, "TXT", 3.0)]


@pytest.mark.parametrize("first,second", [
    ([], []),
    (["correct"], []),
    (["correct"], ["forged"]),
    (["one", "two"], ["one"]),
])
def test_empty_or_divergent_answers_fail_closed(first, second):
    with pytest.raises(ProofError):
        lookup_quorum_txt(
            RECORD, resolver_factory=Mock(side_effect=[
                Resolver(first), Resolver(second),
            ]),
        )


def test_timeout_of_one_resolver_never_accepts_other():
    with pytest.raises(ProofError, match="failed or timed out"):
        lookup_quorum_txt(RECORD, resolver_factory=Mock(side_effect=[
            Resolver(["valid"]), Resolver([], fail=True),
        ]))


def test_invalid_dns_name_never_queried():
    factory = Mock()
    with pytest.raises(ProofError):
        lookup_quorum_txt("localhost", resolver_factory=factory)
    factory.assert_called_once()
