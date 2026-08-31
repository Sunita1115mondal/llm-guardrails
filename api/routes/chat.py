
"""
Guarded LLM chat endpoint.

Pipeline:

    User input
        ↓
    Input guard
        ↓
    LLM
        ↓
    Output guard
        ↓
    Optional schema validation
        ↓
    Safe response
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Request

from api.models.requests import ChatIn
from guardrails.config import MODEL
from guardrails.guard import Guard
from guardrails.schema import (
    SchemaValidationError,
    validate_json,
)


router = APIRouter(
    tags=["Chat"],
)

guard = Guard()

MAX_ATTEMPTS = 3


def _llm(prompt: str) -> str:
    """
    Call Claude when configured.

    Otherwise return a deterministic mock response
    for local development.
    """

    api_key = os.getenv(
        "ANTHROPIC_API_KEY"
    )

    if not api_key:
        return (
            "(mock answer) "
            f"You asked: {prompt[:80]}"
        )

    import anthropic

    client = anthropic.Anthropic(
        api_key=api_key,
    )

    response = client.messages.create(
        model=MODEL,
        max_tokens=512,
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
    )

    return next(
        (
            block.text
            for block in response.content
            if block.type == "text"
        ),
        "",
    )


@router.post(
    "/chat",
    summary="Run a guarded LLM request",
)
def chat(
    body: ChatIn,
    request: Request,
) -> dict:
    """
    Execute the complete guarded LLM pipeline.
    """

    request_id = request.state.request_id

    # ---------------------------------------------------------------
    # INPUT GUARD
    # ---------------------------------------------------------------

    input_verdict = guard.scan_input(
        body.prompt
    )

    if not input_verdict.allowed:
        return {
            "blocked": True,
            "stage": "input",
            "attempts": 0,
            "schema_valid": None,
            "reasons": input_verdict.reasons,
            "answer": (
                "Request blocked by "
                "input guardrail."
            ),
            "request_id": request_id,
            "input_verdict": (
                input_verdict.to_dict()
            ),
        }

    # ---------------------------------------------------------------
    # LLM + OUTPUT GUARD
    # ---------------------------------------------------------------

    current_prompt = input_verdict.text

    for attempt in range(
        1,
        MAX_ATTEMPTS + 1,
    ):

        answer = _llm(
            current_prompt
        )

        output_verdict = (
            guard.scan_output(answer)
        )

        if not output_verdict.allowed:
            return {
                "blocked": True,
                "stage": "output",
                "attempts": attempt,
                "schema_valid": None,
                "reasons": (
                    output_verdict.reasons
                ),
                "answer": (
                    "Response withheld by "
                    "output guardrail."
                ),
                "request_id": request_id,
                "input_verdict": (
                    input_verdict.to_dict()
                ),
                "output_verdict": (
                    output_verdict.to_dict()
                ),
            }

        # -----------------------------------------------------------
        # NO SCHEMA
        # -----------------------------------------------------------

        if body.output_schema is None:
            return {
                "blocked": False,
                "attempts": attempt,
                "schema_valid": None,
                "answer": output_verdict.text,
                "request_id": request_id,
                "input_verdict": (
                    input_verdict.to_dict()
                ),
                "output_verdict": (
                    output_verdict.to_dict()
                ),
            }

        # -----------------------------------------------------------
        # SCHEMA
        # -----------------------------------------------------------

        required_fields = (
            body.output_schema.get(
                "required",
                [],
            )
        )

        try:
            validate_json(
                output_verdict.text,
                required_fields,
            )

            return {
                "blocked": False,
                "attempts": attempt,
                "schema_valid": True,
                "answer": output_verdict.text,
                "request_id": request_id,
                "input_verdict": (
                    input_verdict.to_dict()
                ),
                "output_verdict": (
                    output_verdict.to_dict()
                ),
            }

        except SchemaValidationError as exc:

            if attempt == MAX_ATTEMPTS:
                return {
                    "blocked": True,
                    "stage": "schema",
                    "attempts": attempt,
                    "schema_valid": False,
                    "reasons": [str(exc)],
                    "answer": (
                        "Response did not satisfy "
                        "the required output schema."
                    ),
                    "request_id": request_id,
                    "input_verdict": (
                        input_verdict.to_dict()
                    ),
                    "output_verdict": (
                        output_verdict.to_dict()
                    ),
                }

            current_prompt = (
                "Return a response that satisfies "
                "the required JSON output schema.\n\n"
                f"Required fields: {required_fields}\n\n"
                "Your previous response failed "
                "output validation.\n\n"
                f"Original user request:\n{body.prompt}"
            )

    # Defensive fallback.
    return {
        "blocked": True,
        "stage": "internal",
        "attempts": MAX_ATTEMPTS,
        "schema_valid": False,
        "reasons": [
            "Maximum processing attempts reached."
        ],
        "answer": (
            "Request could not be safely processed."
        ),
        "request_id": request_id,
    }

