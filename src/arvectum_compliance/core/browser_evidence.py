"""Pure, sanitized browser observation contract. No network or browser execution.

Only origin hostnames and counts are persisted; cookie names/values, URL paths,
query parameters and request bodies never enter the stored representation.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Literal
from urllib.parse import urlsplit

Phase = Literal["baseline", "reject", "accept"]


def _safe_host(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Observation URL must be HTTP(S)")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in observation URL are prohibited")
    return parsed.hostname.lower().rstrip(".")


@dataclass(frozen=True, slots=True)
class HostCount:
    host: str
    count: int


@dataclass(frozen=True, slots=True)
class PhaseEvidence:
    phase: Phase
    requests: tuple[HostCount, ...]
    cookies: tuple[HostCount, ...]
    blocked_requests: tuple[HostCount, ...] = ()

    @classmethod
    def from_observations(
        cls,
        phase: Phase,
        request_urls: list[str],
        cookie_domains: list[str],
        blocked_urls: list[str] | None = None,
    ) -> PhaseEvidence:
        if phase not in {"baseline", "reject", "accept"}:
            raise ValueError("Unsupported phase")
        if len(request_urls) > 2000 or len(cookie_domains) > 2000 or len(blocked_urls or []) > 2000:
            raise ValueError("Observation exceeds resource cap")
        request_hosts = Counter(_safe_host(u) for u in request_urls)
        cookie_hosts = Counter()
        for domain in cookie_domains:
            # A cookie domain is an exact host, NOT a URL.
            host = domain.strip().lower().lstrip(".").rstrip(".")
            if not host or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in host):
                raise ValueError("Invalid cookie domain")
            cookie_hosts[host] += 1
        return cls(
            phase=phase,
            requests=tuple(HostCount(k, v) for k, v in sorted(request_hosts.items())),
            cookies=tuple(HostCount(k, v) for k, v in sorted(cookie_hosts.items())),
            blocked_requests=tuple(HostCount(k, v) for k, v in sorted(
                Counter(_safe_host(u) for u in (blocked_urls or [])).items()
            )),
        )


@dataclass(frozen=True, slots=True)
class BrowserReview:
    code: str
    explanation: str
    rule_version: str = "1.0.0"
    status: Literal["review"] = "review"


@dataclass(frozen=True, slots=True)
class ConsentObservation:
    source_host: str
    baseline: PhaseEvidence
    rejected: PhaseEvidence | None
    accepted: PhaseEvidence | None
    reviews: tuple[BrowserReview, ...] = field(default_factory=tuple)
    schema_version: str = "1.0"
    scenario_version: str | None = None
    browser_version: str | None = None
    generated_at: str | None = None
    source_sha256: str | None = None
    limitations: tuple[str, ...] = (
        "Cookie names, values, paths and network URL details are not recorded.",
        "Request counts can include attempts blocked before network transmission.",
        "Observed cookies and requests are not proof of unlawful processing.",
        "An unrecognized consent control means an inconclusive scenario.",
    )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def compare_consent_phases(
    source_url: str,
    baseline: PhaseEvidence,
    rejected: PhaseEvidence | None = None,
    accepted: PhaseEvidence | None = None,
    *,
    scenario_version: str | None = None,
    browser_version: str | None = None,
    generated_at: str | None = None,
    source_sha256: str | None = None,
) -> ConsentObservation:
    source_host = _safe_host(source_url)
    if baseline.phase != "baseline" or (rejected and rejected.phase != "reject"):
        raise ValueError("Phase mismatch")
    if accepted and accepted.phase != "accept":
        raise ValueError("Phase mismatch")
    reviews: list[BrowserReview] = []
    if baseline.cookies:
        reviews.append(BrowserReview(
            "COOKIE-PRE-CONSENT",
            "Cookies were observed before choice; classify their purpose manually.",
        ))
    if rejected is None:
        reviews.append(BrowserReview(
            "CONSENT-REJECT-INCONCLUSIVE",
            "Rejection interaction was not verified; no conclusion can be drawn.",
        ))
    elif any(item.host != source_host for item in rejected.requests):
        reviews.append(BrowserReview(
            "CROSS-HOST-AFTER-REJECT",
            "Cross-host request attempts observed after rejection; may have been blocked.",
        ))
    return ConsentObservation(
        source_host=source_host,
        baseline=baseline,
        rejected=rejected,
        accepted=accepted,
        reviews=tuple(reviews),
        scenario_version=scenario_version,
        browser_version=browser_version,
        generated_at=generated_at,
        source_sha256=source_sha256,
    )
