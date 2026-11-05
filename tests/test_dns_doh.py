"""DoH provider disagreement and malformed response tests (all offline)."""
from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from arvectum_compliance.service import dns_doh
from arvectum_compliance.service.domain_proof import ProofError

RECORD = "_arvectum-compliance.example.com"
VALID = "arvectum-compliance-v1=abc.def-ghi_123"


def payload(*, status=0, value=VALID, hostname=RECORD, type_=16):
    return json.dumps({
        "Status": status,
        "Answer": [{
            "name": hostname + ".", "type": type_, "data": f'"{value}"',
        }] if value else [],
    }).encode()


def test_two_tls_provider_answers_must_agree():
    urls = []

    def fetch(request):
        urls.append(request.full_url)
        return payload()

    assert dns_doh.lookup_doh_quorum_txt(RECORD, fetch=fetch) == [VALID]
    assert len(urls) == 2
    assert urls[0].startswith("https://cloudflare-dns.com/dns-query?")
    assert urls[1].startswith("https://dns.google/resolve?")
    assert "example.com" in urls[0]


@pytest.mark.parametrize("first,second", [
    (payload(value=None), payload()),
    (payload(), payload(value="arvectum-compliance-v1=forged")),
    (payload(status=3, value=None), payload(status=3, value=None)),
    (payload(status=2, value=None), payload()),
])
def test_dns_failure_and_divergence_fail_closed(first, second):
    fetch = Mock(side_effect=[first, second])
    with pytest.raises(ProofError):
        dns_doh.lookup_doh_quorum_txt(RECORD, fetch=fetch)


@pytest.mark.parametrize("response", [
    b"broken", b"{" + b"x" * 17000 + b"}",
    payload(hostname="attacker.example"),
    payload(type_=16, value="value has spaces"),
    payload(value=VALID + '"xx"'),
])
def test_malformed_or_untrusted_dns_txt_response_rejected(response):
    with pytest.raises(ProofError):
        dns_doh.lookup_doh_quorum_txt(RECORD, fetch=lambda _: response)


def test_restricted_record_name_rejected_before_network():
    fetch = Mock()
    with pytest.raises(ProofError):
        dns_doh.lookup_doh_quorum_txt("https://example.com", fetch=fetch)
    fetch.assert_not_called()


def test_split_dns_txt_chunks_are_joined():
    expected = json.dumps({
        "Status": 0,
        "Answer": [{
            "name": RECORD + ".", "type": 16,
            "data": '"arvectum-compliance-v1=abc." "def-ghi_123"',
        }],
    }).encode()
    assert dns_doh.lookup_doh_quorum_txt(RECORD, fetch=lambda _: expected) == [VALID]


def test_https_content_type_is_checked(monkeypatch):
    class Response:
        status = 200
        headers = {"Content-Type": "text/plain"}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, amount):
            return payload()

    opener = Mock()
    opener.open.return_value = Response()
    monkeypatch.setattr(dns_doh.urllib.request, "build_opener", lambda *_: opener)
    with pytest.raises(ProofError, match="HTTP response"):
        dns_doh.lookup_doh_quorum_txt(RECORD)
    opener.open.assert_called_once()
