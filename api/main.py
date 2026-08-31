"""FastAPI firewall API.

Endpoints:
    GET  /health
    GET  /ready
    POST /guard/input
    POST /guard/output
    POST /chat

The API provides:
- request IDs
- safe structured logging
- input/output guardrails
- PII redaction
- secret detection
- prompt-injection detection
- toxicity filtering
- optional JSON schema validation
"""

from __future__ import annotations

import logging
import os
import time
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse

from guardrails.config import MODEL
from guardrails.guard import Guard
from guardrails.schema import SchemaValidationError, validate_json

from api.middleware import RequestIDMiddleware


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("llm_guardrails.api")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="LLM Guardrails",
    version="0.3.0",
    description=(
        "Safety middleware for LLM applications with "
        "input/output guardrails and schema validation."
    ),
)
app.add_middleware(RequestIDMiddleware)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Log request metadata and latency without logging request bodies."""
    start_time = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        duration_ms = (time.perf_counter() - start_time) * 1000
        request_id = getattr(
            request.state,
            "request_id",
            request.headers.get("X-Request-ID"),
        )

        logger.exception(
            "request_failed request_id=%s method=%s path=%s duration_ms=%.2f",
            request_id,
            request.method,
            request.url.path,
            duration_ms,
        )
        raise

    duration_ms = (time.perf_counter() - start_time) * 1000
    request_id = getattr(
        request.state,
        "request_id",
        request.headers.get("X-Request-ID"),
    )

    logger.info(
        "request_complete request_id=%s method=%s path=%s "
        "status=%s duration_ms=%.2f",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )

    response.headers["X-Response-Time-Ms"] = f"{duration_ms:.2f}"
    return response


guard = Guard()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):
    """Return a consistent validation error response."""

    request_id = getattr(
        request.state,
        "request_id",
        None,
    )

    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request validation failed.",
                "request_id": request_id,
                "details": exc.errors(),
            },
            "request_id": request_id,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(
    request: Request,
    exc: Exception,
):
    """Return a safe internal error without exposing implementation details."""

    request_id = getattr(
        request.state,
        "request_id",
        None,
    )

    logger.exception(
        "unhandled_exception",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
        },
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_error",
                "message": "An internal server error occurred.",
                "request_id": request_id,
            },
            "request_id": request_id,
        },
    )


# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------

def _llm(prompt: str) -> str:
    """Call Claude when configured; otherwise return a deterministic mock."""

    api_key = os.getenv("ANTHROPIC_API_KEY")

    if not api_key:
        return f"(mock answer) You asked: {prompt[:80]}"

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
            if getattr(block, "type", None) == "text"
        ),
        "",
    )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TextIn(BaseModel):
    """Request body for direct guard endpoints."""

    model_config = ConfigDict(
        extra="forbid",
    )

    text: str = Field(
        ...,
        min_length=1,
        max_length=50_000,
    )


class ChatIn(BaseModel):
    """Request body for the guarded chat endpoint."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=50_000,
    )

    output_schema: dict | None = Field(
        default=None,
        alias="schema",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _request_id(request: Request) -> str | None:
    """Get the request ID assigned by middleware."""

    return getattr(
        request.state,
        "request_id",
        None,
    )


def _with_request_id(
    request: Request,
    payload: dict,
) -> dict:
    """Attach the request ID to a successful API response."""

    result = dict(payload)

    result["request_id"] = _request_id(request)

    return result


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get(
    "/health",
    tags=["system"],
)
def health(request: Request):
    """Basic liveness check."""

    return _with_request_id(
        request,
        {
            "status": "ok",
            "service": "llm-guardrails",
            "version": "0.3.0",
        },
    )


@app.get(
    "/ready",
    tags=["system"],
)
def ready(request: Request):
    """Readiness check."""

    return _with_request_id(
        request,
        {
            "status": "ready",
            "service": "llm-guardrails",
            "guardrails": "loaded",
        },
    )


# ---------------------------------------------------------------------------
# Input guard
# ---------------------------------------------------------------------------

@app.post(
    "/guard/input",
    tags=["guardrails"],
)
def guard_input(
    body: TextIn,
    request: Request,
):
    """Scan user input for safety and sensitive information."""

    verdict = guard.scan_input(body.text)

    return _with_request_id(
        request,
        verdict.to_dict(),
    )


# ---------------------------------------------------------------------------
# Output guard
# ---------------------------------------------------------------------------

@app.post(
    "/guard/output",
    tags=["guardrails"],
)
def guard_output(
    body: TextIn,
    request: Request,
):
    """Scan LLM output for safety and sensitive information."""

    verdict = guard.scan_output(body.text)

    return _with_request_id(
        request,
        verdict.to_dict(),
    )


# ---------------------------------------------------------------------------
# Guarded chat
# ---------------------------------------------------------------------------

@app.post(
    "/chat",
    tags=["chat"],
)
def chat(
    body: ChatIn,
    request: Request,
):
    """Run a fully guarded LLM interaction."""

    request_id = _request_id(request)

    # ---------------------------------------------------------------
    # 1. INPUT GUARD
    # ---------------------------------------------------------------

    inp = guard.scan_input(body.prompt)

    if not inp.allowed:
        return _with_request_id(
            request,
            {
                "blocked": True,
                "stage": "input",
                "reasons": inp.reasons,
                "answer": "Request blocked by input guardrail.",
                "attempts": 0,
                "input_verdict": inp.to_dict(),
            },
        )

    # ---------------------------------------------------------------
    # 2. LLM + optional schema retry
    # ---------------------------------------------------------------

    max_attempts = 3

    answer = ""
    out = None
    schema_valid = None
    attempt = 0

    required_fields: list[str] = []

    if body.output_schema is not None:
        required_fields = body.output_schema.get(
            "required",
            [],
        )

        if not isinstance(required_fields, list):
            return _with_request_id(
                request,
                {
                    "blocked": True,
                    "stage": "schema",
                    "reasons": [
                        "The schema 'required' field must be a list."
                    ],
                    "answer": "Invalid output schema.",
                    "attempts": 0,
                    "schema_valid": False,
                    "input_verdict": inp.to_dict(),
                },
            )

    for attempt in range(1, max_attempts + 1):

        prompt = inp.text

        if body.output_schema is not None and attempt > 1:
            prompt = (
                "Your previous response failed output validation.\n\n"
                "Return ONLY valid JSON containing these required "
                f"fields: {required_fields}\n\n"
                "Original user request:\n"
                f"{inp.text}"
            )

        answer = _llm(prompt)

        # -----------------------------------------------------------
        # 3. OUTPUT GUARD
        # -----------------------------------------------------------

        out = guard.scan_output(answer)

        if not out.allowed:
            return _with_request_id(
                request,
                {
                    "blocked": True,
                    "stage": "output",
                    "reasons": out.reasons,
                    "answer": "Response withheld by output guardrail.",
                    "attempts": attempt,
                    "schema_valid": (
                        False
                        if body.output_schema is not None
                        else None
                    ),
                    "input_verdict": inp.to_dict(),
                    "output_verdict": out.to_dict(),
                },
            )

        # -----------------------------------------------------------
        # 4. No schema requested
        # -----------------------------------------------------------

        if body.output_schema is None:
            schema_valid = None
            break

        # -----------------------------------------------------------
        # 5. Schema validation
        # -----------------------------------------------------------

        try:
            validate_json(
                out.text,
                required_fields,
            )

            schema_valid = True
            break

        except SchemaValidationError as exc:

            schema_valid = False

            if attempt == max_attempts:
                return _with_request_id(
                    request,
                    {
                        "blocked": True,
                        "stage": "schema",
                        "reasons": [
                            str(exc),
                        ],
                        "answer": (
                            "Response did not satisfy the "
                            "required output schema."
                        ),
                        "attempts": attempt,
                        "schema_valid": False,
                        "input_verdict": inp.to_dict(),
                        "output_verdict": out.to_dict(),
                    },
                )

    # ---------------------------------------------------------------
    # 6. SAFE RESPONSE
    # ---------------------------------------------------------------

    return _with_request_id(
        request,
        {
            "blocked": False,
            "answer": out.text if out is not None else answer,
            "attempts": attempt,
            "schema_valid": schema_valid,
            "input_verdict": inp.to_dict(),
            "output_verdict": out.to_dict() if out is not None else None,
        },
    )

