"""
Shield Service Application — Local Isolated Processing API.

Exposes the isolated Shield service endpoints:
- GET  /health              (Circuit state & health status)
- POST /v1/shield/process   (Local Judge pre-check → SofaShieldFast inference → Post-Judge sanitization)
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status

from shield.config import ShieldConfig
from shield.judge import LocalJudge
from shield.models import (
    CircuitState,
    JudgeVerdict,
    ShieldHealthResponse,
    ShieldRequest,
    ShieldResponse,
)
from shield.shield_fast import (
    CircuitBreakerOpenError,
    ShieldBackendError,
    ShieldRequestValidationError,
    SofaShieldFast,
)

logger = logging.getLogger("shield")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage lifecycle of the Shield service."""
    config = ShieldConfig()
    app.state.config = config
    app.state.judge = LocalJudge()
    app.state.shield_fast = SofaShieldFast(config=config)
    logger.info("Shield service initialized in [%s] mode on port %d", config.shield_mode, config.port)
    yield
    await app.state.shield_fast.client.aclose()
    logger.info("Shield service shutdown completed")


app = FastAPI(
    title="Shield Service",
    description="Local isolated inference & safety evaluation service",
    version="2.0.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=ShieldHealthResponse, tags=["Health"])
async def health_check() -> ShieldHealthResponse:
    """Check health and circuit breaker status of the Shield service."""
    shield_fast: SofaShieldFast = app.state.shield_fast
    state = shield_fast.get_circuit_state()

    is_healthy = state != CircuitState.OPEN
    return ShieldHealthResponse(
        status="healthy" if is_healthy else "unhealthy",
        circuit_state=state,
        service="shield",
    )


@app.post(
    "/v1/shield/process",
    response_model=ShieldResponse,
    responses={
        400: {"description": "Request validation error"},
        403: {"description": "Rejected by Local Judge (Pre or Post check)"},
        502: {"description": "Local LLM inference backend failure"},
        503: {"description": "Circuit breaker OPEN - Shield unavailable"},
    },
    tags=["Shield"],
)
async def process_request(request_data: ShieldRequest) -> ShieldResponse:
    """
    Process restricted request inside the isolated Shield environment.

    Execution Flow:
    1. Local Judge Pre-Check (DENY on dangerous commands / code execution).
    2. SofaShieldFast Local Inference (Strict local/private model endpoint).
    3. Local Judge Post-Check (DENY on private key leak, REDACT on SSN/Credit Card, ALLOW on clean).
    """
    start_time = time.perf_counter()
    judge: LocalJudge = app.state.judge
    shield_fast: SofaShieldFast = app.state.shield_fast
    config: ShieldConfig = app.state.config

    messages = request_data.messages

    # --- Step 1: Local Judge Pre-LLM Check ---
    pre_verdict = judge.evaluate_request(messages)
    if pre_verdict == JudgeVerdict.DENY:
        logger.warning("Shield: Request rejected by Local Judge (Pre-Check DENY)")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Request rejected by Local Judge: dangerous execution pattern detected",
        )

    # --- Step 2: SofaShieldFast Local Inference ---
    try:
        raw_response = await shield_fast.infer(messages)
    except CircuitBreakerOpenError as e:
        logger.error("Shield: Circuit breaker OPEN: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Shield backend unavailable — circuit breaker OPEN",
        )
    except ShieldRequestValidationError as e:
        logger.warning("Shield: Request validation error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except ShieldBackendError as e:
        logger.error("Shield: Local LLM backend error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Local LLM backend error: {e}",
        )

    # --- Step 3: Local Judge Post-LLM Check & Redaction ---
    post_verdict = judge.evaluate_response(raw_response)
    if post_verdict == JudgeVerdict.DENY:
        logger.warning("Shield: Response rejected by Local Judge (Post-Check DENY - Secret Leak)")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Response rejected by Local Judge: critical secret leak detected",
        )

    if post_verdict == JudgeVerdict.REDACT:
        final_text = judge.redact_response(raw_response)
        logger.info("Shield: Response sanitized (REDACT)")
    else:
        final_text = raw_response

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return ShieldResponse(
        response=final_text,
        judge_verdict=post_verdict,
        processing_time_ms=round(elapsed_ms, 2),
        model_used=config.local_llm_model,
    )


def run():
    """Run Shield service with uvicorn."""
    import uvicorn
    cfg = ShieldConfig()
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level=cfg.log_level.lower())


if __name__ == "__main__":
    run()
