"""Stable v1 output, without SaaS or transport coupling."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

Severity = Literal["info", "medium", "high"]


@dataclass(frozen=True, slots=True)
class Evidence:
    url: str
    selector: str
    observation: str


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    rule_version: str
    severity: Severity
    status: Literal["review"]
    title: str
    explanation: str
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class Signals:
    forms: int
    personal_data_forms: int
    policy_links: int
    consent_controls: int
    external_actions: int


@dataclass(frozen=True, slots=True)
class ScanReport:
    source_url: str
    findings: tuple[Finding, ...]
    signals: Signals
    limitations: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
