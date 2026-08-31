
"""Prompt-injection and jailbreak detection.

Uses explainable heuristic signatures to detect:

- instruction overrides
- system/developer prompt extraction
- jailbreak personas
- safety-policy bypasses
- priority manipulation
- hidden/internal instruction requests

The detector intentionally avoids flagging harmless educational
mentions such as:

    "What is a system prompt?"

as prompt injection.
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

_SIGNATURES = [

    # ---------------------------------------------------------------
    # 1. Instruction override
    # ---------------------------------------------------------------
    (
        0.80,
        re.compile(
            r"\b("
            r"ignore|disregard|forget|override"
            r")\b"
            r".{0,60}"
            r"\b("
            r"previous|prior|above|earlier|old|original|existing"
            r")\b"
            r".{0,40}"
            r"\b("
            r"instructions?|rules?|policy|prompt|commands?"
            r")\b",
            re.I,
        ),
        "instruction_override",
    ),

    # Direct "override your instructions"
    (
        0.80,
        re.compile(
            r"\boverride\b"
            r".{0,40}"
            r"\b(your|the|existing|current|previous)\s+"
            r"instructions?\b",
            re.I,
        ),
        "instruction_override",
    ),

    # "follow only my commands"
    (
        0.80,
        re.compile(
            r"\b("
            r"follow only|obey only|listen only to|"
            r"follow these commands"
            r")\b"
            r".{0,50}"
            r"\b(my|these|user)\s*(commands?|instructions?)?\b",
            re.I,
        ),
        "instruction_override",
    ),

    # Explicit replacement of instructions
    (
        0.85,
        re.compile(
            r"\b("
            r"follow|use|obey"
            r")\b"
            r".{0,30}"
            r"\b(new|these)\s+instructions?\b",
            re.I,
        ),
        "instruction_override",
    ),

    # "Do not follow your previous instructions"
    (
        0.85,
        re.compile(
            r"\b("
            r"do not|don't|dont"
            r")\s+"
            r"\bfollow\b"
            r".{0,40}"
            r"\b(previous|prior|old|original|earlier)\s+"
            r"instructions?\b",
            re.I,
        ),
        "instruction_override",
    ),

    # ---------------------------------------------------------------
    # 2. Prompt / instruction exfiltration
    # ---------------------------------------------------------------

    # IMPORTANT:
    # This requires an extraction verb.
    #
    # Therefore:
    #   "What is a system prompt?"
    #
    # is NOT flagged.
    (
        0.85,
        re.compile(
            r"\b("
            r"reveal|show|print|display|repeat|output|expose|"
            r"give me|tell me|provide|share"
            r")\b"
            r".{0,80}"
            r"\b("
            r"system prompt|system message|developer message|"
            r"developer instructions?|hidden prompt|internal instructions?|"
            r"confidential instructions?|initial prompt|"
            r"your prompt|your instructions|instructions you were given"
            r")\b",
            re.I,
        ),
        "prompt_exfiltration",
    ),

    # Reverse ordering:
    # "system prompt ... reveal it"
    (
        0.85,
        re.compile(
            r"\b("
            r"system prompt|system message|developer message|"
            r"hidden prompt|internal instructions?|"
            r"confidential instructions?|initial prompt"
            r")\b"
            r".{0,60}"
            r"\b("
            r"reveal|show|print|display|repeat|output|expose|"
            r"give|share"
            r")\b",
            re.I,
        ),
        "prompt_exfiltration",
    ),

    # "What was the hidden system prompt?"
    (
        0.85,
        re.compile(
            r"\bwhat\s+was\b"
            r".{0,60}"
            r"\b("
            r"hidden|system|developer|internal|initial"
            r")\b"
            r".{0,30}"
            r"\b("
            r"prompt|message|instructions?"
            r")\b",
            re.I,
        ),
        "prompt_exfiltration",
    ),

    # ---------------------------------------------------------------
    # 3. "System message does not exist" manipulation
    # ---------------------------------------------------------------
    (
        0.85,
        re.compile(
            r"\b("
            r"system message does not exist|"
            r"system prompt does not exist|"
            r"ignore your system message|"
            r"ignore the system message|"
            r"pretend the system message does not exist|"
            r"act as if your system message does not exist"
            r")\b",
            re.I,
        ),
        "system_prompt_manipulation",
    ),

    # ---------------------------------------------------------------
    # 4. Jailbreak personas
    # ---------------------------------------------------------------
    (
        0.85,
        re.compile(
            r"\b("
            r"you are now|act as|pretend to be|roleplay as"
            r")\b"
            r".{0,80}"
            r"\b("
            r"DAN|jailbroken|unrestricted|developer mode|"
            r"no restrictions|without restrictions"
            r")\b",
            re.I,
        ),
        "jailbreak_persona",
    ),

    # Standalone jailbreak requests
    (
        0.80,
        re.compile(
            r"\b("
            r"unrestricted mode|developer mode|"
            r"jailbreak|jailbroken|no restrictions|"
            r"without restrictions|do anything now"
            r")\b",
            re.I,
        ),
        "jailbreak_persona",
    ),

    # ---------------------------------------------------------------
    # 5. Safety bypass
    # ---------------------------------------------------------------
    (
        0.85,
        re.compile(
            r"\b("
            r"ignore|bypass|override|disable|remove|circumvent"
            r")\b"
            r".{0,50}"
            r"\b("
            r"safety|guardrails?|content policy|filters?|"
            r"restrictions?|security policy"
            r")\b",
            re.I,
        ),
        "safety_bypass",
    ),

    # ---------------------------------------------------------------
    # 6. Priority manipulation
    # ---------------------------------------------------------------
    (
        0.85,
        re.compile(
            r"\b("
            r"treat my message as the highest[- ]priority instruction|"
            r"treat this as the highest[- ]priority instruction|"
            r"highest[- ]priority instruction|"
            r"higher priority than your instructions|"
            r"system[- ]level instruction"
            r")\b",
            re.I,
        ),
        "priority_manipulation",
    ),

    # ---------------------------------------------------------------
    # 7. Delimiter / fake system messages
    # ---------------------------------------------------------------
    (
        0.70,
        re.compile(
            r"\bnew instructions?:\s*"
            r"|"
            r"\bsystem:\s*"
            r"|"
            r"\bdeveloper:\s*",
            re.I,
        ),
        "delimiter_injection",
    ),

    # ---------------------------------------------------------------
    # 8. Constraint removal
    # ---------------------------------------------------------------
    (
        0.65,
        re.compile(
            r"\b("
            r"without|no"
            r")\b"
            r".{0,25}"
            r"\b("
            r"ethical|moral|legal"
            r")\b"
            r".{0,25}"
            r"\b("
            r"constraints?|limitations?|concerns?"
            r")\b",
            re.I,
        ),
        "constraint_removal",
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score(text: str) -> dict:
    """Return an explainable prompt-injection risk score.

    Returns:
        {
            "score": float,
            "signals": list[str]
        }
    """

    if not isinstance(text, str):
        return {
            "score": 0.0,
            "signals": [],
        }

    matched: list[str] = []
    total = 0.0

    for weight, pattern, label in _SIGNATURES:
        if pattern.search(text):
            matched.append(label)
            total += weight

    # Multiple independent signals increase confidence.
    if len(matched) > 1:
        total += 0.05 * (len(matched) - 1)

    return {
        "score": round(min(total, 1.0), 3),
        "signals": sorted(set(matched)),
    }

