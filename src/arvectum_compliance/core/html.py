"""Bounded HTML structural parsing. Never retain input values or visitor data."""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

_POLICY = ("privacy", "policy", "personal-data", "pdn", "политик", "персональн")
_PERSONAL = ("email", "phone", "tel", "name", "fio", "имя", "телефон", "почта")
_CONSENT = ("consent", "соглас", "privacy", "персональн", "agree")


@dataclass(slots=True)
class FormSignal:
    index: int
    action: str
    personal: bool = False
    consent: bool = False

    def external(self, source_url: str) -> bool:
        if not self.action:
            return False
        candidate = urlsplit(urljoin(source_url, self.action))
        source = urlsplit(source_url)
        return candidate.scheme not in ("http", "https") or candidate.netloc != source.netloc


@dataclass(slots=True)
class PageSignals:
    forms: list[FormSignal] = field(default_factory=list)
    policy_links: int = 0


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.result = PageSignals()
        self.form: FormSignal | None = None
        self.anchor: str | None = None
        self.anchor_text: list[str] = []
        self.policy_hrefs: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {key: (value or "")[:250] for key, value in attrs}
        if tag == "form":
            self.form = FormSignal(len(self.result.forms) + 1, a.get("action", ""))
            self.result.forms.append(self.form)
        elif tag == "a":
            self.anchor = a.get("href", "")
            self.anchor_text = []
        if self.form is not None and tag in {"input", "textarea", "select"}:
            kind = a.get("type", "").lower()
            identifier = (a.get("name", "") + " " + a.get("id", "")).lower()
            if kind in {"email", "tel"} or any(h in identifier for h in _PERSONAL):
                self.form.personal = True
            if kind in {"checkbox", "radio"} and any(h in identifier for h in _CONSENT):
                self.form.consent = True

    def handle_data(self, data: str) -> None:
        if self.anchor is not None and len(self.anchor_text) < 4:
            self.anchor_text.append(data[:120])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.form = None
        if tag == "a" and self.anchor is not None:
            text = (" ".join(self.anchor_text) + " " + self.anchor).casefold()
            if self.anchor and any(h in text for h in _POLICY):
                self.policy_hrefs.add(self.anchor.casefold())
            self.anchor = None
            self.anchor_text = []

    def close(self) -> None:
        super().close()
        self.result.policy_links = len(self.policy_hrefs)


def extract_signals(html: str) -> PageSignals:
    if len(html.encode("utf-8")) > 2_000_000:
        raise ValueError("HTML exceeds 2 MB limit")
    parser = _Parser()
    parser.feed(html)
    parser.close()
    return parser.result
