"""PII detection + redaction (deterministic regex; no external service).

Each detector returns spans so the guard can redact in place. Validators (Luhn for cards,
structural checks) cut false positives — the metric that actually matters for a redactor.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"\b(?:\+?\d{1,2}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
CREDIT_CARD = re.compile(r"\b(?:\d[ -]?){13,16}\b")


@dataclass
class Span:
    type: str
    start: int
    end: int
    text: str


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def detect(text: str) -> list[Span]:
    spans: list[Span] = []
    for kind, rx in (("email", EMAIL), ("ssn", SSN), ("ipv4", IPV4), ("phone", PHONE)):
        for m in rx.finditer(text):
            spans.append(Span(kind, m.start(), m.end(), m.group()))
    for m in CREDIT_CARD.finditer(text):
        if _luhn(m.group()):  # Luhn check kills most false positives
            spans.append(Span("credit_card", m.start(), m.end(), m.group()))
    # de-overlap: keep the longest span when two detectors hit the same region
    spans.sort(key=lambda s: (s.start, -(s.end - s.start)))
    kept: list[Span] = []
    for s in spans:
        if not any(s.start < k.end and s.end > k.start for k in kept):
            kept.append(s)
    return kept


def redact(text: str, spans: list[Span] | None = None) -> str:
    spans = spans if spans is not None else detect(text)
    out = text
    for s in sorted(spans, key=lambda s: s.start, reverse=True):
        out = out[:s.start] + f"[{s.type.upper()}]" + out[s.end:]
    return out
