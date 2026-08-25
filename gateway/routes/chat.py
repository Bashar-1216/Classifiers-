"""
Chat completions route — Main API endpoint.

This is the primary entry point for all AI requests.
Every request flows through the full production pipeline:
  Gateway → Classifier (Semantic + Specialized + Rules) → Policy → Router → Output Safety → Audit Telemetry (PRD §7)
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse

from gateway.models.schemas import ChatRequest, ChatResponse, ErrorResponse
from gateway.observability import AuditLogger
from router.shield_backend import ShieldUnavailableError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Chat"])


@router.post(
    "/v1/chat/completions",
    response_model=ChatResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid API key"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        503: {"model": ErrorResponse, "description": "Shield/backend unavailable"},
    },
)
async def chat_completions(
    chat_request: ChatRequest,
    request: Request,
) -> ChatResponse | JSONResponse:
    """
    Process a chat completion request through the Secure AI Gateway.

    Pipeline:
    1. Authentication (handled by middleware/dependency)
    2. Rate limiting (handled by middleware/dependency)
    3. Classification — analyze request for multi-dimensional risks (Semantic, Specialized, Context, Metadata, Rules)
    4. Policy decision — determine routing (NORMAL/CLOUD or SHIELD/LOCAL_SHIELD)
    5. Routing — send to appropriate backend
    6. Output Safety — evaluate and sanitize response for secrets/PII/exploits
    7. Response & Audit Telemetry — record zero-leakage hash & metrics
    """
    request_id = uuid.uuid4().hex
    start_time = time.monotonic()

    logger.info(
        "[%s] Processing chat request (%d messages)",
        request_id[:8],
        len(chat_request.messages),
    )

    try:
        # --- Step 1: Extract text for classification ---
        full_text = chat_request.get_full_text()

        # --- Step 2: Risk Assessment (Semantic, Specialized Detectors, Context, Metadata, Rules) ---
        classifier = request.app.state.classifier
        messages_dicts = [{"role": m.role, "content": m.content} for m in chat_request.messages]
        metadata_dict = chat_request.metadata.model_dump() if chat_request.metadata else {}

        classification_result = classifier.classify(
            text=full_text,
            messages=messages_dicts,
            metadata=metadata_dict,
        )

        logger.info(
            "[%s] Classification: %s (confidence=%.4f, risk_score=%.4f)",
            request_id[:8],
            classification_result.classification.value,
            classification_result.confidence,
            classification_result.risk_score,
        )

        # --- Step 3: Declarative Policy Decision ---
        policy_engine = request.app.state.policy_engine
        decision = policy_engine.evaluate(classification_result, metadata=metadata_dict)

        logger.info(
            "[%s] Policy: route=%s — %s",
            request_id[:8],
            decision.route.value,
            decision.reason,
        )

        # --- Step 4: Route to backend ---
        router_service = request.app.state.router_service
        response = await router_service.route(decision, chat_request)

        # --- Step 5: Output Safety Filtering & Sanitization ---
        output_safety = getattr(request.app.state, "output_safety", None)
        output_verdict = "ALLOW"
        output_modified = False

        if output_safety and response.choices:
            raw_content = response.choices[0].message.content or ""
            safety_res = output_safety.evaluate(raw_content)
            output_verdict = safety_res.verdict.value
            output_modified = safety_res.is_modified

            if safety_res.is_modified:
                response.choices[0].message.content = safety_res.sanitized_text
                logger.info(
                    "[%s] OutputSafety applied: verdict=%s, modified=%s",
                    request_id[:8],
                    output_verdict,
                    output_modified,
                )

        # Add request tracking
        response.request_id = request_id

        elapsed = (time.monotonic() - start_time) * 1000

        # --- Step 6: Emit Zero-Leakage Audit Telemetry & Metrics ---
        AuditLogger.log_event(
            request_id=request_id,
            duration_ms=elapsed,
            risk_score=classification_result.risk_score or classification_result.confidence,
            categories=classification_result.categories,
            reasons=classification_result.reasons,
            route=response.route_taken or decision.route.value,
            policy_reason=decision.reason,
            metadata=metadata_dict,
            model=chat_request.model,
            prompt_text=full_text,
            output_verdict=output_verdict,
            output_modified=output_modified,
            status_code=200,
        )

        logger.info(
            "[%s] Response: route=%s, output_safety=%s, time=%.0fms",
            request_id[:8],
            response.route_taken,
            output_verdict,
            elapsed,
        )

        return response

    except ShieldUnavailableError as e:
        # Shield failed — FAIL CLOSED (SR-3)
        elapsed = (time.monotonic() - start_time) * 1000
        logger.error(
            "[%s] FAIL CLOSED: Shield unavailable — %s (%.0fms)",
            request_id[:8],
            str(e),
            elapsed,
        )
        return JSONResponse(
            status_code=503,
            content=ErrorResponse(
                error="shield_unavailable",
                code="FAIL_CLOSED",
                detail=str(e),
                request_id=request_id,
            ).model_dump(),
        )

    except Exception as e:
        elapsed = (time.monotonic() - start_time) * 1000
        logger.error(
            "[%s] Unexpected error: %s (%.0fms)",
            request_id[:8],
            str(e),
            elapsed,
        )
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="internal_error",
                code="GATEWAY_ERROR",
                detail=f"An internal error occurred: {type(e).__name__}",
                request_id=request_id,
            ).model_dump(),
        )
