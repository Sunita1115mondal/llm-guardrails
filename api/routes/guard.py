
"""
Guardrail API endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from api.models.requests import TextIn
from guardrails.guard import Guard


router = APIRouter(
    prefix="/guard",
    tags=["Guardrails"],
)

guard = Guard()


@router.post(
    "/input",
    summary="Scan user input",
)
def guard_input(
    body: TextIn,
    request: Request,
) -> dict:
    """
    Scan user input for:

    - Prompt injection
    - PII
    - Secrets
    - Toxicity
    """

    verdict = guard.scan_input(
        body.text
    )

    result = verdict.to_dict()

    result["request_id"] = (
        request.state.request_id
    )

    return result


@router.post(
    "/output",
    summary="Scan LLM output",
)
def guard_output(
    body: TextIn,
    request: Request,
) -> dict:
    """
    Scan an LLM completion for
    sensitive or unsafe content.
    """

    verdict = guard.scan_output(
        body.text
    )

    result = verdict.to_dict()

    result["request_id"] = (
        request.state.request_id
    )

    return result

