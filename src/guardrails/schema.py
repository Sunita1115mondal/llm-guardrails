"""Output schema validation for LLM responses."""
from __future__ import annotations

import json
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when an LLM response does not match the required schema."""


def validate_json(text: str, required_fields: list[str]) -> dict[str, Any]:
    """Validate that text is JSON and contains required top-level fields."""

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaValidationError(
            f"Invalid JSON: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise SchemaValidationError(
            "Expected a JSON object."
        )

    missing = [
        field
        for field in required_fields
        if field not in data
    ]

    if missing:
        raise SchemaValidationError(
            f"Missing required fields: {', '.join(missing)}"
        )

    return data