"""
Router Service — Executes routing decisions.

Takes a PolicyDecision and the original request, then dispatches
to the appropriate backend (Normal or Shield). (PRD §6.6)
"""

from __future__ import annotations

import logging
from typing import Any

from policy.models import PolicyDecision, Route
from router.normal_backend import NormalBackend
from router.shield_backend import ShieldBackend, ShieldUnavailableError
from schemas import ChatChoice, ChatRequest, ChatResponse, Message

logger = logging.getLogger(__name__)


class RouterService:
    """
    Dispatches requests to the appropriate backend based on policy decision.

    Routes:
    - NORMAL / CLOUD → NormalBackend (cloud AI)
    - SHIELD / LOCAL_SHIELD → ShieldBackend (local isolated processing)
    """

    def __init__(
        self,
        normal_backend: NormalBackend,
        shield_backend: ShieldBackend,
    ) -> None:
        self.normal_backend = normal_backend
        self.shield_backend = shield_backend

    async def route(
        self,
        decision: PolicyDecision,
        request: ChatRequest,
    ) -> ChatResponse:
        """
        Route a request based on the policy decision.

        Args:
            decision: The routing decision from PolicyEngine.
            request: The original chat request.

        Returns:
            ChatResponse with the AI-generated response and routing metadata.

        Raises:
            ShieldUnavailableError: When Shield fails (fail closed — no fallback).
        """
        messages = [
            {"role": msg.role, "content": msg.content}
            for msg in request.messages
        ]

        # If only prompt is provided (no messages), wrap it as a user message
        if not messages and request.prompt:
            messages = [{"role": "user", "content": request.prompt}]

        # 1. Strict PEP Integrity & Provenance Verification
        req_id = request.request_id or (request.metadata.request_id if request.metadata else None)
        if decision.signature is not None:
            is_valid, err_msg = decision.verify_integrity(expected_request_id=req_id)
            if not is_valid:
                logger.error("PEP Decision Integrity Violation: %s — Failing Closed", err_msg)
                raise ShieldUnavailableError(f"Decision Integrity Violation: {err_msg}")

        # Invariant checks for Restricted and Shield Routes
        if decision.route in (Route.RESTRICTED, Route.SHIELD, Route.LOCAL_SHIELD):
            if decision.cloud_fallback:
                logger.error("PEP Invariant Violation: cloud_fallback=True on RESTRICTED route")
                raise ShieldUnavailableError("PEP Invariant Violation: cloud_fallback=True on RESTRICTED route")
            if any("cloud" in d.lower() for d in decision.permitted_destinations):
                logger.error("PEP Destination Violation: cloud destination listed in RESTRICTED decision")
                raise ShieldUnavailableError("PEP Destination Violation: cloud destination listed in RESTRICTED decision")

        if decision.route in (Route.NORMAL, Route.CLOUD):
            return await self._route_normal(messages, request, decision)
        elif decision.route in (Route.RESTRICTED, Route.SHIELD, Route.LOCAL_SHIELD, Route.LOCAL_PRIVATE):
            return await self._route_shield(messages, request, decision)
        elif decision.route == Route.BLOCK:
            logger.warning("Request BLOCKED by PDP: %s", decision.reason)
            return ChatResponse(
                choices=[
                    ChatChoice(
                        index=0,
                        message=Message(role="assistant", content=f"Request blocked by enterprise security policy: {decision.reason}"),
                        finish_reason="stop",
                    )
                ],
                route_taken="BLOCK",
                model="security_gateway",
            )
        elif decision.route == Route.UNAVAILABLE:
            logger.error("Shield UNAVAILABLE — Failing closed with zero cloud fallback")
            raise ShieldUnavailableError("Air-Gapped Shield service is unavailable. Request denied (Fail-Closed).")
        else:
            # Unknown route — fail closed
            logger.error("Unknown route: %s — failing closed", decision.route)
            raise ShieldUnavailableError(f"Unknown route: {decision.route}")

    async def _route_normal(
        self,
        messages: list[dict[str, str]],
        request: ChatRequest,
        decision: PolicyDecision,
    ) -> ChatResponse:
        """Route to normal AI backend."""
        logger.info("Routing to NORMAL backend")

        try:
            kwargs: dict[str, Any] = {}
            if request.model:
                kwargs["model"] = request.model
            if request.temperature is not None:
                kwargs["temperature"] = request.temperature
            if request.max_tokens is not None:
                kwargs["max_tokens"] = request.max_tokens

            result = await self.normal_backend.send(messages, **kwargs)

            # Parse OpenAI-compatible response
            response_text = self._extract_response_text(result)

            return ChatResponse(
                model=result.get("model"),
                choices=[
                    ChatChoice(
                        index=0,
                        message=Message(role="assistant", content=response_text),
                        finish_reason=result.get("choices", [{}])[0].get(
                            "finish_reason", "stop"
                        ) if result.get("choices") else "stop",
                    )
                ],
                route_taken="NORMAL",
            )

        except Exception as e:
            logger.error("Normal backend error: %s", e)
            raise

    async def _route_shield(
        self,
        messages: list[dict[str, str]],
        request: ChatRequest,
        decision: PolicyDecision,
    ) -> ChatResponse:
        """
        Route to Shield backend for local processing.

        On ANY failure: raise ShieldUnavailableError.
        NEVER fall back to normal/cloud backend. (SR-3)
        """
        logger.info("Routing to SHIELD backend")

        metadata: dict[str, Any] | None = None
        if request.metadata:
            metadata = request.metadata.model_dump()

        classification_data: dict[str, Any] | None = None
        if decision.classification_result:
            classification_data = decision.classification_result.model_dump()

        # This will raise ShieldUnavailableError on failure — no fallback
        result = await self.shield_backend.send(
            messages=messages,
            metadata=metadata,
            classification_result=classification_data,
        )

        response_text = result.get("response")
        if response_text is None:
            raise ShieldUnavailableError(
                "Shield response missing 'response' text. FAIL CLOSED: No cloud fallback."
            )

        return ChatResponse(
            choices=[
                ChatChoice(
                    index=0,
                    message=Message(role="assistant", content=response_text),
                    finish_reason="stop",
                )
            ],
            route_taken="SHIELD",
            model=result.get("model_used"),
        )

    def _extract_response_text(self, result: dict[str, Any]) -> str:
        """Extract the response text from an OpenAI-compatible response."""
        try:
            choices = result.get("choices", [])
            if choices:
                message = choices[0].get("message", {})
                return message.get("content", "")
        except (IndexError, KeyError, TypeError):
            pass
        # Fallback: check for direct response field
        return result.get("response", "")

    async def close(self) -> None:
        """Close all backend connections."""
        await self.normal_backend.close()
        await self.shield_backend.close()
        logger.info("Router backends closed")
