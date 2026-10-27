
"""Application-level team access control and rate limiting for Bayora."""

import hmac
import logging
import os
import threading
import time
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from api.bayora_audit import record_audit_event, verify_audit_log

logger = logging.getLogger("llm_guardrails.bayora_security")

router = APIRouter(prefix="/bayora", tags=["Bayora security"])

# In-memory rate-limit state. Separate counters are maintained per team.
_rate_limit_lock = threading.Lock()
_team_request_counts: dict[str, tuple[float, int]] = {}


def authenticate_team(
    request: Request,
    authorization: str | None = Header(default=None),
) -> str:
    """Identify a team using its configured bearer token."""

    red_token = os.getenv("BAYORA_RED_TEAM_TOKEN", "")
    blue_token = os.getenv("BAYORA_BLUE_TEAM_TOKEN", "")

    # Fail closed when tokens are missing or identical.
    if (
        not red_token
        or not blue_token
        or hmac.compare_digest(red_token, blue_token)
    ):
        logger.error(
            "bayora_auth_unavailable request_id=%s",
            getattr(request.state, "request_id", None),
        )
        raise HTTPException(
            status_code=503,
            detail="Team authentication is not configured.",
        )

    if not authorization or not authorization.startswith("Bearer "):
        logger.warning(
            "bayora_access_denied request_id=%s reason=missing_credentials",
            getattr(request.state, "request_id", None),
        )
        raise HTTPException(
            status_code=401,
            detail="Valid bearer credentials are required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    supplied_token = authorization[len("Bearer "):]

    if hmac.compare_digest(supplied_token, red_token):
        return "red"

    if hmac.compare_digest(supplied_token, blue_token):
        return "blue"

    logger.warning(
        "bayora_access_denied request_id=%s reason=invalid_credentials",
        getattr(request.state, "request_id", None),
    )
    raise HTTPException(
        status_code=401,
        detail="Invalid credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def enforce_team_rate_limit(
    request: Request,
    authenticated_team: str = Depends(authenticate_team),
) -> str:
    """Enforce a configurable request limit for each authenticated team."""

    try:
        max_requests = max(
            1, int(os.getenv("BAYORA_RATE_LIMIT_REQUESTS", "10"))
        )
    except ValueError:
        max_requests = 10

    try:
        window_seconds = max(
            1.0,
            float(os.getenv("BAYORA_RATE_LIMIT_WINDOW_SECONDS", "60")),
        )
    except ValueError:
        window_seconds = 60.0

    now = time.monotonic()

    with _rate_limit_lock:
        window_start, count = _team_request_counts.get(
            authenticated_team, (now, 0)
        )

        # Reset the team's counter when its window expires.
        if now - window_start >= window_seconds:
            window_start, count = now, 0

        if count >= max_requests:
            retry_after = max(
                1, int(window_seconds - (now - window_start)) + 1
            )

            logger.warning(
                "bayora_rate_limit_exceeded team=%s request_id=%s",
                authenticated_team,
                getattr(request.state, "request_id", None),
            )

            raise HTTPException(
                status_code=429,
                detail="Team request limit exceeded. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )

        _team_request_counts[authenticated_team] = (
            window_start,
            count + 1,
        )

    return authenticated_team


@router.get("/private/{team}")
def get_private_resource(
    team: Literal["red", "blue"],
    request: Request,
    authenticated_team: str = Depends(enforce_team_rate_limit),
):
    """Allow a team to access only its own demonstration resource."""

    request_id = getattr(request.state, "request_id", None)

    # Deny and audit cross-team access attempts.
    if authenticated_team != team:
        record_audit_event(
            request_id=request_id,
            actor=authenticated_team,
            target=team,
            outcome="denied",
            event_type="cross_team_access",
        )

        logger.warning(
            "bayora_access_denied request_id=%s actor=%s "
            "target=%s reason=cross_team_access",
            request_id,
            authenticated_team,
            team,
        )

        raise HTTPException(
            status_code=403,
            detail="Access to another team's resource is forbidden.",
        )

    # Audit successful access.
    record_audit_event(
        request_id=request_id,
        actor=authenticated_team,
        target=team,
        outcome="allowed",
        event_type="resource_access",
    )

    logger.info(
        "bayora_access_allowed request_id=%s actor=%s target=%s",
        request_id,
        authenticated_team,
        team,
    )

    return {
        "team": team,
        "resource": f"{team}-team-private-demo",
        "access": "granted",
        "request_id": request_id,
    }


def authenticate_audit_admin(
    authorization: str | None = Header(default=None),
) -> None:
    """Require a separate token to verify audit-log integrity."""

    admin_token = os.getenv("BAYORA_AUDIT_ADMIN_TOKEN", "")

    if not admin_token:
        raise HTTPException(
            status_code=503,
            detail="Audit verification is not configured.",
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Valid audit administrator credentials are required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    supplied_token = authorization[len("Bearer "):]

    if not hmac.compare_digest(supplied_token, admin_token):
        raise HTTPException(
            status_code=401,
            detail="Invalid audit administrator credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/audit/verify", tags=["Bayora audit"])
def verify_audit_integrity(
    _: None = Depends(authenticate_audit_admin),
):
    """Verify the integrity of the persistent audit log."""

    result = verify_audit_log()

    logger.info(
        "bayora_audit_verification valid=%s records_checked=%s",
        result["valid"],
        result["records_checked"],
    )

    return result
