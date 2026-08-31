
"""Configuration and policy management for the LLM guardrails firewall."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Paths and model configuration
# ---------------------------------------------------------------------------

ROOT = Path(
    os.getenv(
        "GUARD_ROOT",
        Path(__file__).resolve().parents[2],
    )
)

CASES_PATH = ROOT / "data" / "cases.yaml"

MODEL = os.getenv(
    "GUARD_MODEL",
    "claude-opus-4-8",
)
VERSION = "0.3.0"

# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    """Runtime policy used by the LLM guardrail pipeline."""

    injection_threshold: float = 0.6
    toxicity_threshold: float = 0.5

    block_on_input_secret: bool = True
    redact_pii: bool = True
    use_llm_toxicity: bool = False

    categories: list[str] = field(
        default_factory=lambda: [
            "injection",
            "pii",
            "toxicity",
            "secrets",
        ]
    )

    # -----------------------------------------------------------------------
    # Default policy
    # -----------------------------------------------------------------------

    @classmethod
    def default(cls) -> "Policy":
        """Return the built-in secure default policy."""

        return cls(
            injection_threshold=0.6,
            toxicity_threshold=0.5,
            block_on_input_secret=True,
            redact_pii=True,
            use_llm_toxicity=False,
            categories=[
                "injection",
                "pii",
                "toxicity",
                "secrets",
            ],
        )

    # -----------------------------------------------------------------------
    # YAML policy loader
    # -----------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        """Load a policy from a YAML configuration file.

        Supports both flat policies and structured policies.

        Structured example:

            name: default

            settings:
              injection_threshold: 0.6
              toxicity_threshold: 0.5
              block_on_input_secret: true
              redact_pii: true
              use_llm_toxicity: false

            input:
              categories:
                - injection
                - pii
                - toxicity
                - secrets

            output:
              categories:
                - pii
                - secrets
                - toxicity
        """

        policy_path = Path(path)

        if not policy_path.is_absolute():
            policy_path = ROOT / policy_path

        if not policy_path.exists():
            raise FileNotFoundError(
                f"Policy file not found: {policy_path}"
            )

        with policy_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data: Any = yaml.safe_load(file)

        if data is None:
            data = {}

        if not isinstance(data, dict):
            raise ValueError(
                "Policy YAML must contain a mapping at the top level."
            )

        # Start from secure defaults.
        defaults = cls.default()

        values = {
            "injection_threshold": defaults.injection_threshold,
            "toxicity_threshold": defaults.toxicity_threshold,
            "block_on_input_secret": defaults.block_on_input_secret,
            "redact_pii": defaults.redact_pii,
            "use_llm_toxicity": defaults.use_llm_toxicity,
            "categories": list(defaults.categories),
        }

        # -------------------------------------------------------------------
        # 1. Read settings section
        # -------------------------------------------------------------------

        settings = data.get("settings", {})

        if settings is None:
            settings = {}

        if not isinstance(settings, dict):
            raise ValueError(
                "'settings' must be a mapping."
            )

        # Allow direct/flat policy files too.
        source = {
            **{
                key: value
                for key, value in data.items()
                if key in values
            },
            **settings,
        }

        for key in values:
            if key in source:
                values[key] = source[key]

        # -------------------------------------------------------------------
        # 2. Read categories from input/output sections
        # -------------------------------------------------------------------

        input_config = data.get("input", {})
        output_config = data.get("output", {})

        if input_config is None:
            input_config = {}

        if output_config is None:
            output_config = {}

        if not isinstance(input_config, dict):
            raise ValueError("'input' must be a mapping.")

        if not isinstance(output_config, dict):
            raise ValueError("'output' must be a mapping.")

        # If categories are explicitly defined in input/output,
        # combine them without duplicates.
        category_values: list[str] = []

        for section in (input_config, output_config):
            section_categories = section.get("categories")

            if section_categories is None:
                continue

            if isinstance(section_categories, str):
                section_categories = [section_categories]

            if not isinstance(section_categories, list):
                raise ValueError(
                    "Policy categories must be a list."
                )

            for category in section_categories:
                category = str(category)

                if category not in category_values:
                    category_values.append(category)

        if category_values:
            values["categories"] = category_values

        # -------------------------------------------------------------------
        # 3. Normalize values
        # -------------------------------------------------------------------

        values["injection_threshold"] = float(
            values["injection_threshold"]
        )

        values["toxicity_threshold"] = float(
            values["toxicity_threshold"]
        )

        if not 0.0 <= values["injection_threshold"] <= 1.0:
            raise ValueError(
                "injection_threshold must be between 0.0 and 1.0."
            )

        if not 0.0 <= values["toxicity_threshold"] <= 1.0:
            raise ValueError(
                "toxicity_threshold must be between 0.0 and 1.0."
            )

        if not isinstance(values["block_on_input_secret"], bool):
            raise ValueError(
                "block_on_input_secret must be true or false."
            )

        if not isinstance(values["redact_pii"], bool):
            raise ValueError(
                "redact_pii must be true or false."
            )

        if not isinstance(values["use_llm_toxicity"], bool):
            raise ValueError(
                "use_llm_toxicity must be true or false."
            )

        values["categories"] = [
            str(category)
            for category in values["categories"]
        ]

        return cls(**values)


# ---------------------------------------------------------------------------
# Global default policy
# ---------------------------------------------------------------------------

DEFAULT_POLICY = Policy.default()

