from __future__ import annotations

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):
    """Return a consistent response for invalid API requests."""

    request_id = getattr(request.state, "request_id", None)

    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "type": "validation_error",
                "message": "Request validation failed.",
                "request_id": request_id,
                "details": exc.errors(),
            }
        },
    )


async def general_exception_handler(
    request: Request,
    exc: Exception,
):
    """Prevent internal exception details from leaking through the API."""

    request_id = getattr(request.state, "request_id", None)

    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "type": "internal_error",
                "message": "An internal server error occurred.",
                "request_id": request_id,
            }
        },
    )