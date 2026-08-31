"""llm-guardrails — an input/output firewall for LLM apps.

Scans prompts and completions for PII, prompt-injection / jailbreaks, secrets, and toxic
content; blocks or redacts per policy; and ships a labeled benchmark so every detector's
precision/recall is measured, not asserted.
"""

__version__ = "0.1.0"
