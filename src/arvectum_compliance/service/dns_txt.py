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


def lookup_quorum_txt(
    record_name: str, *, resolver_factory=None,
) -> list[str]:
    """Fail-closed DNS TXT lookup from independent public recursive resolvers.

    Both must return the identical complete TXT record set. This is NOT
    cryptographic DNSSEC validation. Use trusted resolver networking and an
    independent security review before public multi-tenant deployment.
    """
    # DNS spoofing and propagation uncertainty must never turn into success.
    resolvers = ("1.1.1.1", "9.9.9.9")
    if resolver_factory is None:
        try:
            import dns.resolver
        except ImportError as exc:
            raise ProofError("Install optional DNS resolver dependency") from exc

        def resolver_factory(nameserver: str):
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [nameserver]
            resolver.timeout = 2.0
            resolver.lifetime = 3.0
            return resolver

    seen: list[set[str]] = []
    for nameserver in resolvers:
        values = lookup_ownership_txt(
            record_name, resolver=resolver_factory(nameserver),
        )
        if not values:
            raise ProofError("Ownership DNS TXT not present on both resolvers")
        seen.append(set(values))
    if seen[0] != seen[1]:
        raise ProofError("Ownership DNS TXT disagrees across resolvers")
    return sorted(seen[0])
