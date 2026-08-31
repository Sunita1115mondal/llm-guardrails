
"""
Health and service-status endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter


from guardrails.config import VERSION


router = APIRouter(
    tags=["Health"]
)


@router.get(
    "/health",
    summary="Health check",
)
def health() -> dict[str, str]:
    """
    Return service health information.
    """

    return {
        "status": "ok",
        "service": "llm-guardrails",
        "version": VERSION,
    }

