"""
Secure AI Gateway — Main Application.

The central entry point for the Secure AI Gateway system.
All requests flow through this application, which orchestrates:
  Authentication → Rate Limiting → Risk Assessment → Policy → Routing → Output Safety
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from classifier.service import ClassifierService
from gateway.config import Settings
from gateway.metrics import MetricsCollector
from gateway.middleware.auth import AuthMiddleware
from gateway.middleware.rate_limit import RateLimiter
from gateway.models.schemas import ErrorResponse
from gateway.routes import chat, health
from output_safety.engine import OutputSafetyEngine
from policy.engine import PolicyEngine
from router.normal_backend import NormalBackend
from router.service import RouterService
from router.shield_backend import ShieldBackend


def setup_logging(log_level: str) -> None:
    """Configure structured logging."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan — initialize and cleanup services.
    """
    settings = Settings()
    setup_logging(settings.log_level)

    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("  Secure AI Gateway — Starting up (Full Production Architecture)")
    logger.info("=" * 60)

    # --- Initialize services ---

    # Risk Assessment Classifier (Semantic, Specialized Detectors, Context, Metadata, Rules)
    classifier = ClassifierService(
        rules_dir=settings.rules_dir,
        confidence_threshold=settings.confidence_threshold,
    )

    # Policy Engine
    policy_engine = PolicyEngine()

    # Output Safety Layer
    output_safety = OutputSafetyEngine()

    # Router backends
    normal_backend = NormalBackend(
        backend_url=settings.normal_backend_url,
        api_key=settings.normal_backend_api_key or None,
        default_model=settings.normal_backend_model,
        timeout=settings.normal_backend_timeout,
    )
    shield_backend = ShieldBackend(
        shield_url=settings.shield_service_url,
        timeout=settings.shield_timeout,
    )
    router_service = RouterService(
        normal_backend=normal_backend,
        shield_backend=shield_backend,
    )

    # Auth + Rate Limiter
    auth_middleware = AuthMiddleware(valid_api_keys=settings.api_keys_list)
    rate_limiter = RateLimiter(requests_per_minute=settings.rate_limit_per_minute)

    # Store on app.state for access in routes
    app.state.settings = settings
    app.state.classifier = classifier
    app.state.policy_engine = policy_engine
    app.state.output_safety = output_safety
    app.state.router_service = router_service
    app.state.auth_middleware = auth_middleware
    app.state.rate_limiter = rate_limiter

    logger.info("Gateway ready on %s:%d", settings.host, settings.port)
    logger.info("  Rules loaded: %d", len(classifier.rule_engine.rules))
    logger.info("  Specialized Detectors: PII, Jailbreak, Safety active")
    logger.info("  Output Safety: Secrets, PII, Policy active")
    logger.info("  Normal backend: %s", settings.normal_backend_url)
    logger.info("  Shield service: %s", settings.shield_service_url)
    logger.info("  Rate limit: %d req/min", settings.rate_limit_per_minute)
    logger.info("  API keys configured: %d", len(settings.api_keys_list))
    logger.info("=" * 60)

    yield

    # --- Cleanup ---
    logger.info("Gateway shutting down...")
    await router_service.close()
    logger.info("Gateway shutdown complete")


# --- Dependency: Auth + Rate Limit ---

async def verify_auth_and_rate_limit(request: Request) -> str:
    """
    FastAPI dependency that enforces authentication and rate limiting.
    """
    api_key = await request.app.state.auth_middleware.verify(request)
    await request.app.state.rate_limiter.check(request, api_key)
    return api_key


# --- Create FastAPI app ---

app = FastAPI(
    title="Secure AI Gateway",
    description=(
        "Production-grade secure AI routing system. "
        "Classifies requests, applies declarative governance policies, "
        "routes safely, and enforces post-generation output safety."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """Ensure every request has a correlation ID propagated across logs and response headers."""
    import uuid
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# Register routes
app.include_router(health.router)
app.include_router(
    chat.router,
    dependencies=[Depends(verify_auth_and_rate_limit)],
)


# --- Observability Endpoints (Prometheus & JSON Metrics) ---

@app.get("/metrics", response_class=PlainTextResponse, tags=["Observability"])
async def get_prometheus_metrics() -> str:
    """Prometheus exposition format metrics for scraping."""
    return MetricsCollector().generate_prometheus()


@app.get("/metrics/json", tags=["Observability"])
async def get_json_metrics() -> JSONResponse:
    """JSON summary of gateway performance, threat detection, and route telemetry."""
    return JSONResponse(content=MetricsCollector().get_summary())


# --- Global exception handler ---

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all exception handler — never leak internal errors."""
    logger = logging.getLogger(__name__)
    logger.error("Unhandled exception: %s — %s", type(exc).__name__, str(exc))
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_error",
            code="GATEWAY_ERROR",
            detail="An internal error occurred",
        ).model_dump(),
    )


def run() -> None:
    """Entry point for running the gateway."""
    settings = Settings()
    uvicorn.run(
        "gateway.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        reload=False,
    )


if __name__ == "__main__":
    run()
