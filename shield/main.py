"""
Shield Service — Main FastAPI Application.

Runs the isolated Shield service that processes restricted AI requests locally
using LocalJudge + SofaShieldFast + Local LLM.
Operates strictly in an isolated network with Fail-Closed security.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from shield.config import ShieldConfig
from shield.judge import LocalJudge
from shield.models import CircuitState, JudgeVerdict, ShieldHealthResponse, ShieldRequest, ShieldResponse
from shield.shield_fast import (
    CircuitBreakerOpenError,
    ShieldBackendError,
    ShieldRequestValidationError,
    SofaShieldFast,
)

logger = logging.getLogger("shield")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Manage the lifecycle of the Shield application.

    Initializes configuration, LocalJudge, and SofaShieldFast on startup,
    and cleanly releases resources on shutdown.
    """
    config = ShieldConfig()
    judge = LocalJudge()
    shield_fast = SofaShieldFast(config=config)

    app.state.config = config
    app.state.judge = judge
    app.state.shield_fast = shield_fast

    logger.info(
        "Shield service startup complete. Binding on %s:%d, Local LLM: %s (%s)",
        config.host,
        config.port,
        config.local_llm_url,
        config.local_llm_model,
    )

    yield

    logger.info("Shield service shutting down...")
    await shield_fast.close()
    logger.info("Shield service shutdown complete.")


app = FastAPI(
    title="Secure AI Gateway — Shield Service",
    description="Isolated processing environment for RESTRICTED requests with Local Judge and sofa-shield-fast",
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Standardize HTTP exception responses in Fail-Closed manner."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "ShieldServiceError",
            "code": f"HTTP_{exc.status_code}",
            "detail": exc.detail,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Fail-Closed catch-all handler for unexpected internal errors."""
    logger.error("Unhandled exception in Shield service: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "ShieldInternalError",
            "code": "INTERNAL_ERROR",
            "detail": "An internal error occurred during local shield processing",
        },
    )


@app.post(
    "/v1/shield/process",
    response_model=ShieldResponse,
    status_code=status.HTTP_200_OK,
    summary="Process restricted requests via Local Judge and Local LLM",
    responses={
        200: {"description": "Request successfully processed and evaluated"},
        400: {"description": "Validation error or request size exceeded"},
        403: {"description": "Request or response rejected by Local Judge"},
        502: {"description": "Local LLM backend error or unreachable"},
        503: {"description": "Shield backend unavailable - circuit breaker open"},
    },
)
async def process_request(request: ShieldRequest) -> ShieldResponse:
    """
    Process incoming restricted requests through the local secure pipeline.

    Pipeline:
    1. Pre-LLM evaluation: LocalJudge checks request for dangerous patterns.
    2. Local Inference: SofaShieldFast calls local LLM through circuit breaker.
    3. Post-LLM evaluation: LocalJudge checks response for PII/secrets.
    4. Format & Return: Returns ShieldResponse with timing and verdict.
    5. Fail Closed: Any failure returns an explicit error response; NEVER clouds fallback.
    """
    start_time = time.perf_counter()
    judge: LocalJudge = app.state.judge
    shield_fast: SofaShieldFast = app.state.shield_fast
    config: ShieldConfig = app.state.config

    # 1. Pre-LLM safety evaluation via LocalJudge
    req_verdict = judge.evaluate_request(request.messages)
    if req_verdict == JudgeVerdict.DENY:
        logger.warning("Request rejected by Local Judge pre-LLM check (verdict=DENY)")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Request rejected by local judge: dangerous patterns detected",
        )

    # 2. Local LLM inference via SofaShieldFast
    try:
        raw_response = await shield_fast.infer(request.messages)
    except CircuitBreakerOpenError as exc:
        logger.error("Inference aborted due to open circuit: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except ShieldRequestValidationError as exc:
        logger.warning("Request validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except ShieldBackendError as exc:
        logger.error("Shield local backend error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error("Unexpected error during local shield inference: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Local shield inference failed unexpectedly",
        ) from exc

    # 3. Post-LLM safety evaluation via LocalJudge
    resp_verdict = judge.evaluate_response(raw_response)
    if resp_verdict == JudgeVerdict.DENY:
        logger.warning("Response rejected by Local Judge post-LLM check (verdict=DENY)")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Response rejected by local judge: dangerous content detected",
        )
    elif resp_verdict == JudgeVerdict.REDACT:
        logger.info("Response contains PII; redacting response text (verdict=REDACT)")
        final_response = judge.redact_response(raw_response)
        final_verdict = JudgeVerdict.REDACT
    else:
        final_response = raw_response
        final_verdict = JudgeVerdict.ALLOW

    # 4. Return ShieldResponse with latency measurement
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    return ShieldResponse(
        response=final_response,
        judge_verdict=final_verdict,
        processing_time_ms=elapsed_ms,
        model_used=config.local_llm_model,
    )


@app.get(
    "/health",
    response_model=ShieldHealthResponse,
    summary="Health check and circuit breaker status",
)
async def health() -> ShieldHealthResponse:
    """
    Return the operational status and circuit breaker state of the Shield service.
    """
    shield_fast: SofaShieldFast = app.state.shield_fast
    state = shield_fast.get_circuit_state()
    status_str = (
        "healthy"
        if state == CircuitState.CLOSED
        else ("degraded" if state == CircuitState.HALF_OPEN else "unhealthy")
    )
    return ShieldHealthResponse(
        status=status_str,
        circuit_state=state,
        service="shield",
    )


def run() -> None:
    """Entry point to launch the Shield service via Uvicorn."""
    config = ShieldConfig()
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info(
        "Launching Shield service on %s:%d (log_level=%s)",
        config.host,
        config.port,
        config.log_level,
    )
    uvicorn.run(
        "shield.main:app",
        host=config.host,
        port=config.port,
        log_level=config.log_level.lower(),
        reload=False,
    )
