
"""Toxicity and harmful-content detection.

Combines:
- toxic/abusive language
- self-harm requests
- violent-harm requests
- malware requests
- account theft
- destructive malicious-code requests
- threatening content
"""

from __future__ import annotations

import os
import re


_TOXIC = {
    "idiot": 0.5,
    "stupid": 0.4,
    "moron": 0.5,
    "loser": 0.4,
    "shut up": 0.4,
    "i hate you": 0.6,
    "kill yourself": 1.0,
    "go die": 0.9,
    "worthless": 0.6,
}


_BANNED_TOPICS = {
    "weapons": re.compile(
        r"\b(build|make|synthesize|create).{0,30}"
        r"\b(bomb|explosive|weapon)\b",
        re.I,
    ),

    "self_harm": re.compile(
        r"\b(how to|ways to|instructions? for|help me).{0,30}"
        r"\b(kill myself|suicide|self[- ]harm)\b",
        re.I,
    ),

    "malware": re.compile(
        r"\b(write|create|generate|make|develop|build).{0,30}"
        r"\b(malware|ransomware|keylogger|virus|malicious code)\b",
        re.I,
    ),

    "violence": re.compile(
        r"\b("
        r"hurt someone|hurt another person|"
        r"attack someone|violently attack|"
        r"physical violence|"
        r"seriously hurt someone"
        r")\b",
        re.I,
    ),

    "threats": re.compile(
        r"\b("
        r"threatening message|threaten someone|"
        r"threatening another person|"
        r"message threatening physical violence"
        r")\b",
        re.I,
    ),

    "abuse": re.compile(
        r"\b("
        r"abusive message|"
        r"hateful insults|"
        r"insults aimed at|"
        r"targeting another person"
        r")\b",
        re.I,
    ),

    "account_theft": re.compile(
        r"\b("
        r"steal someone's account|"
        r"stealing someone's account|"
        r"take over someone's account|"
        r"account takeover"
        r")\b",
        re.I,
    ),

    "security_evasion": re.compile(
        r"\b("
        r"evade security|"
        r"avoid security|"
        r"bypass security"
        r").{0,40}"
        r"\b(attack|crime|malicious)\b",
        re.I,
    ),
}


def score(text: str) -> dict:
    """Return a deterministic toxicity/harm score."""

    if not isinstance(text, str):
        return {
            "score": 0.0,
            "flagged": False,
            "terms": [],
            "banned_topics": [],
        }

    low = text.lower()

    hits = {
        word: severity
        for word, severity in _TOXIC.items()
        if word in low
    }

    topics = [
        topic
        for topic, pattern in _BANNED_TOPICS.items()
        if pattern.search(text)
    ]

    severity = max(
        [
            *hits.values(),
            *([1.0] if topics else [0.0]),
        ],
        default=0.0,
    )

    flagged = bool(topics) or severity >= 0.5

    return {
        "score": round(severity, 3),
        "flagged": flagged,
        "terms": sorted(hits),
        "banned_topics": topics,
    }


def llm_judge(text: str) -> dict:
    """Optional Claude-based classifier.

    Falls back to the deterministic detector when no API key exists.
    """

    if not os.getenv("ANTHROPIC_API_KEY"):
        return score(text)

    import anthropic

    client = anthropic.Anthropic()

    response = client.messages.create(
        model=os.getenv("GUARD_MODEL", "claude-opus-4-8"),
        max_tokens=16,
        system=(
            "You are a content-safety classifier. "
            "Return ONLY a number from 0 to 1 representing "
            "the probability that the text contains toxic, "
            "violent, malicious, or otherwise unsafe content."
        ),
        messages=[
            {
                "role": "user",
                "content": text,
            }
        ],
    )

    raw = next(
        (
            block.text
            for block in response.content
            if block.type == "text"
        ),
        "0",
    ).strip()

    match = re.search(r"\b(?:0(?:\.\d+)?|1(?:\.0+)?)\b", raw)

    try:
        value = float(match.group()) if match else 0.0
    except ValueError:
        value = 0.0

    return {
        "score": round(value, 3),
        "flagged": value >= 0.5,
        "terms": [],
        "banned_topics": [],
    }

