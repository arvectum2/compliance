"""Conservative, reproducible technical heuristics: NOT legal certification."""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from .html import extract_signals
from .models import Evidence, Finding, ScanReport, Signals

LIMITATIONS = (
    "Static HTML cannot show JavaScript-generated cookies or network requests.",
    "Server processing, data residency, and internal policies were not inspected.",
    "Findings require human review and are not findings of legal infringement.",
)


def scan_html(source_url: str, html: str) -> ScanReport:
    parsed = urlsplit(source_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("source_url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are prohibited")
    # Query/fragment may carry bearer tokens and are never written to reports.
    safe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    signals = extract_signals(html)
    findings: list[Finding] = []

    def add(rule: str, version: str, severity: str, title: str, reason: str, n: int) -> None:
        findings.append(Finding(
            rule_id=rule,
            rule_version=version,
            severity=severity,  # type: ignore[arg-type]
            status="review",
            title=title,
            explanation=reason,
            evidence=Evidence(safe_url, f"xpath:(//form)[{n}]", "Form structure only"),
        ))

    for form in signals.forms:
        if form.personal and not signals.policy_links:
            add("WEB-POLICY-LINK", "1.0.0", "medium",
                "No recognizable privacy-policy link on this HTML page",
                "Check site-wide links and dynamically rendered information manually.",
                form.index)
        if form.personal and not form.consent:
            add("WEB-CONSENT-SIGNAL", "1.0.0", "info",
                "No obvious consent checkbox in form markup",
                "Consent is not always the required legal basis; verify actual processing basis.",
                form.index)
        if form.external(source_url):
            add("WEB-EXTERNAL-FORM", "1.0.0", "medium",
                "Form action points outside current origin or uses another protocol",
                "Inspect the destination and legal basis; no submission was performed.",
                form.index)
    findings.sort(key=lambda f: (f.evidence.selector, f.rule_id))
    return ScanReport(
        source_url=safe_url,
        findings=tuple(findings),
        signals=Signals(
            forms=len(signals.forms),
            personal_data_forms=sum(f.personal for f in signals.forms),
            policy_links=signals.policy_links,
            consent_controls=sum(f.consent for f in signals.forms),
            external_actions=sum(f.external(source_url) for f in signals.forms),
        ),
        limitations=LIMITATIONS,
    )
