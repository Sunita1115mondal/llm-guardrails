
"""
API request models.

All externally supplied request data is validated here
before reaching the guardrail or LLM layer.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TextIn(BaseModel):
    """Request containing text to scan."""

    model_config = ConfigDict(
        extra="forbid",
    )

    text: str = Field(
        ...,
        min_length=1,
        max_length=50_000,
        description="Text to scan.",
    )


class ChatIn(BaseModel):
    """Request for a guarded LLM conversation."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=50_000,
        description="User prompt.",
    )

    output_schema: dict[str, Any] | None = Field(
        default=None,
        alias="schema",
        description=(
            "Optional output schema. "
            "The API accepts the legacy JSON field name 'schema'."
        ),
    )

