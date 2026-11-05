"""Explicit server-side DNS TXT adapter; offline core and tests remain DNS-free."""
from __future__ import annotations

from .domain_proof import ProofError, canonical_hostname


def lookup_ownership_txt(
    record_name: str,
    *,
    resolver=None,
) -> list[str]:
    """Query TXT with strict size limits. Caller must trust the selected resolver.

    In production, use a protected resolver / multiple independent resolvers,
    with network firewall and monitoring. This is not DNSSEC verification.
    """
    label = "_arvectum-compliance."
    if not isinstance(record_name, str) or not record_name.startswith(label):
        raise ProofError("Only the ownership TXT location may be queried")
    hostname = canonical_hostname(record_name[len(label):])
    queried = label + hostname
    if resolver is None:
        try:
            import dns.resolver
        except ImportError as exc:
            raise ProofError("Install optional DNS resolver dependency") from exc
        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = 3.0
        resolver.timeout = 2.0
    try:
        results = resolver.resolve(queried, "TXT", lifetime=3.0)
    except Exception as exc:
        # No DNS raw values/hostnames in logged exceptions.
        raise ProofError("Ownership DNS lookup failed or timed out") from exc
    entries: list[str] = []
    for item in results:
        if len(entries) >= 64:
            raise ProofError("Too many TXT answers")
        parts = getattr(item, "strings", None)
        if not isinstance(parts, (list, tuple)):
            raise ProofError("Invalid DNS TXT answer")
        blob = b"".join(parts)
        if len(blob) > 512:
            raise ProofError("TXT value too large")
        try:
            entries.append(blob.decode("ascii", errors="strict"))
        except UnicodeError as exc:
            raise ProofError("Non-ASCII TXT content") from exc
    return entries
