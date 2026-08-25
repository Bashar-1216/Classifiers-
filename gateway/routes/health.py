"""
Health check routes.

Provides liveness and readiness probes for the Gateway. (PRD §6.1)
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check() -> dict[str, str]:
    """
    Liveness probe — returns 200 if the Gateway process is up.
    """
    return {"status": "alive"}


@router.get("/health/ready")
async def readiness_check(request: Request) -> dict[str, object]:
    """
    Readiness probe — checks if backends are reachable.

    Returns overall status and individual component health.
    """
    components: dict[str, str] = {}

    # Check Shield backend
    try:
        router_service = request.app.state.router_service
        shield_ok = await router_service.shield_backend.health_check()
        components["shield"] = "ok" if shield_ok else "unavailable"
    except Exception:
        components["shield"] = "unavailable"

    # Check classifier
    try:
        classifier = request.app.state.classifier
        components["classifier"] = "ok" if classifier else "not_initialized"
        components["rules_loaded"] = str(len(classifier.rule_engine.rules))
    except Exception:
        components["classifier"] = "not_initialized"

    overall = "ready" if all(v == "ok" for k, v in components.items() if k != "rules_loaded") else "degraded"

    return {
        "status": overall,
        "components": components,
    }
