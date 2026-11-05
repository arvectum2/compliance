"""Strict bridge from the no-network Playwright fixture to reusable core evidence."""
from __future__ import annotations

import json
import re
from datetime import datetime

from arvectum_compliance.core.browser_evidence import (
    ConsentObservation,
    HostCount,
    PhaseEvidence,
    compare_consent_phases,
)

_HOST = re.compile(r"^[a-z0-9.-]{1,253}$")
_TOP = {
    "schema_version", "fixture", "source_host", "browser", "network_mode",
    "baseline", "rejected", "accepted", "limitations",
    "scenario_version", "generated_at", "source_sha256", "browser_version",
}
_PHASE = {"phase", "requests", "cookies", "blocked"}
_ALLOWED_FIXTURES = {"consent.html", "attack.html", "inconclusive.html"}


def _host_counts(items: object) -> tuple[HostCount, ...]:
    if not isinstance(items, list) or len(items) > 200:
        raise ValueError("Invalid host count list")
    result: list[HostCount] = []
    total = 0
    seen: set[str] = set()
    for entry in items:
        if not isinstance(entry, dict) or set(entry) != {"host", "count"}:
            raise ValueError("Invalid host count record")
        host, count = entry["host"], entry["count"]
        if (
            not isinstance(host, str)
            or not _HOST.fullmatch(host)
            or host in seen
            or type(count) is not int
            or count <= 0
        ):
            raise ValueError("Invalid or duplicate hostname/count")
        seen.add(host)
        total += count
        result.append(HostCount(host, count))
    if total > 200:
        raise ValueError("Exceeded browser request cap")
    return tuple(sorted(result, key=lambda v: v.host))


def _parse_phase(name: str, data: object) -> PhaseEvidence | None:
    if data is None:
        return None
    if not isinstance(data, dict) or set(data) != _PHASE:
        raise ValueError("Unexpected phase fields")
    expected = "reject" if name == "rejected" else "accept" if name == "accepted" else "baseline"
    if data["phase"] != expected:
        raise ValueError("Browser phase mismatch")
    return PhaseEvidence(
        phase=expected,
        requests=_host_counts(data["requests"]),
        cookies=_host_counts(data["cookies"]),
        blocked_requests=_host_counts(data["blocked"]),
    )


def parse_fixture_json(document: str) -> ConsentObservation:
    if len(document.encode("utf-8")) > 60_000:
        raise ValueError("Browser output limit exceeded")
    raw = json.loads(document)
    if not isinstance(raw, dict) or set(raw) != _TOP:
        raise ValueError("Unexpected browser output fields")
    if (
        raw["schema_version"] != "1.0"
        or raw["browser"] != "chromium"
        or raw["network_mode"] != "none"
        or raw["source_host"] != "compliance-fixture.invalid"
        or raw["fixture"] not in _ALLOWED_FIXTURES
    ):
        raise ValueError("Untrusted browser output")
    if (
        raw["scenario_version"] != "0.1.0"
        or not isinstance(raw["browser_version"], str)
        or not re.fullmatch(r"[0-9.]{1,50}", raw["browser_version"])
        or not isinstance(raw["source_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", raw["source_sha256"])
    ):
        raise ValueError("Invalid browser source/version metadata")
    if not isinstance(raw["generated_at"], str):
        raise ValueError("Missing generated timestamp")
    try:
        timestamp = datetime.fromisoformat(raw["generated_at"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("Browser timestamp must include an offset")
    except ValueError as exc:
        raise ValueError("Invalid browser timestamp") from exc
    baseline = _parse_phase("baseline", raw["baseline"])
    rejected = _parse_phase("rejected", raw["rejected"])
    accepted = _parse_phase("accepted", raw["accepted"])
    if baseline is None:
        raise ValueError("Baseline required")
    return compare_consent_phases(
        "https://compliance-fixture.invalid/", baseline, rejected, accepted,
        scenario_version=raw["scenario_version"],
        browser_version=raw["browser_version"],
        generated_at=raw["generated_at"],
        source_sha256=raw["source_sha256"],
    )
