
"""Secret and credential detection.

Detects common API keys, tokens, passwords, client secrets,
and database connection strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretSpan:
    """A detected secret and its location in the input text."""

    type: str
    start: int
    end: int
    text: str

    def __eq__(self, other):
        """Allow compatibility checks such as 'aws_access_key' in detect(...)."""

        if isinstance(other, str):
            return self.type == other

        if isinstance(other, SecretSpan):
            return (
                self.type == other.type
                and self.start == other.start
                and self.end == other.end
                and self.text == other.text
            )

        return NotImplemented


# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------


_PATTERNS = [
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "anthropic_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "generic_api_key",
        re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{12,}\b"),
    ),
    (
        "api_key",
        re.compile(
            r"\bapi[-_ ]?key\b(?:\s*[:=]\s*|\s+is\s+)"
            r"[A-Za-z0-9_-]{8,}",
            re.IGNORECASE,
        ),
    ),
    (
        "client_secret",
        re.compile(
            r"\bclient[-_ ]?secret\b\s*[:=]\s*[A-Za-z0-9_-]{8,}",
            re.IGNORECASE,
        ),
    ),
    (
        "password",
        re.compile(
            r"\bpassword\b\s*[:=]\s*[^\s,;]{6,}",
            re.IGNORECASE,
        ),
    ),
    (
        "database_url",
        re.compile(
            r"\bDATABASE_URL\s*=\s*"
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)"
            r"://[^\s]+",
            re.IGNORECASE,
        ),
    ),
]

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detect(text: str) -> list[SecretSpan]:
    """Return non-overlapping detected secret spans."""
    if not isinstance(text, str):
        return []

    candidates: list[SecretSpan] = []

    for secret_type, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            candidates.append(
                SecretSpan(
                    type=secret_type,
                    start=match.start(),
                    end=match.end(),
                    text=match.group(),
                )
            )

    # Prefer the longest match when patterns overlap.
    candidates.sort(
        key=lambda item: (item.start, -(item.end - item.start))
    )

    findings: list[SecretSpan] = []
    for candidate in candidates:
        if findings and candidate.start < findings[-1].end:
            continue
        findings.append(candidate)

    return findings



# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

_REPLACEMENTS = {
    "generic_api_key": "[API_KEY]",
    "aws_access_key": "[AWS_ACCESS_KEY]",
    "anthropic_key": "[ANTHROPIC_KEY]",
    "github_token": "[GITHUB_TOKEN]",
    "api_key": "[API_KEY]",
    "password": "[PASSWORD]",
    "client_secret": "[CLIENT_SECRET]",
    "database_url": "[DATABASE_URL]",
}


def redact(text: str) -> str:
    """Replace detected secrets with safe placeholders."""

    if not isinstance(text, str):
        return text

    findings = detect(text)

    if not findings:
        return text

    result = text

    # Replace from right to left so earlier positions remain valid.
    for span in sorted(
        findings,
        key=lambda item: item.start,
        reverse=True,
    ):
        replacement = _REPLACEMENTS.get(
            span.type,
            "[SECRET]",
        )

        result = (
            result[:span.start]
            + replacement
            + result[span.end:]
        )

    return result

