"""
FastAPI Application for Local Guard Microservice.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from services.guard.config import GuardServiceConfig
from services.guard.models import EvaluationRequest, EvaluationResponse, HealthResponse
from services.guard.backend import GuardInferenceBackend

logger = logging.getLogger("guard_service")
logging.basicConfig(level=logging.INFO)

config = GuardServiceConfig()
backend = GuardInferenceBackend(config)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        if os.getenv("AUTOLOAD_GUARD_MODEL", "false").lower() == "true":
            backend.load_model()
    except Exception as exc:
        logger.warning("Could not autoload Guard model on startup: %s", exc)
    yield


app = FastAPI(title="Local Neural Guard Service", version="1.0.0", lifespan=lifespan)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ready" if backend.is_ready else "initializing",
        model_id=config.model_id,
        device=backend.device,
    )


@app.post("/v1/evaluate", response_model=EvaluationResponse)
async def evaluate(req: EvaluationRequest):
    if not backend.is_ready:
        try:
            backend.load_model()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Guard model loading failed: {exc}")

    try:
        verdict_text, latency_ms = backend.evaluate_prompt(req.prompt)
        return EvaluationResponse(
            verdict_text=verdict_text,
            confidence=1.0,
            model_id=config.model_id,
            model_revision="main",
            latency_ms=round(latency_ms, 2),
        )
    except Exception as exc:
        logger.error("Inference failure: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.host, port=config.port)
