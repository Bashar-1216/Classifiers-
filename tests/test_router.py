"""
Router tests — PRD §6.6.

Tests:
- Normal routing works
- Shield routing works
- Shield failure → error (NOT cloud fallback) — SR-3
"""

from __future__ import annotations

import pytest

from unittest.mock import AsyncMock, patch

from classifier.models import Classification, ClassificationResult
from gateway.models.schemas import ChatRequest, Message
from policy.models import PolicyDecision, Route
from router.service import RouterService
from router.normal_backend import NormalBackend
from router.shield_backend import ShieldBackend, ShieldUnavailableError


@pytest.fixture
def mock_normal_backend() -> AsyncMock:
    backend = AsyncMock(spec=NormalBackend)
    backend.send.return_value = {
        "choices": [
            {"message": {"role": "assistant", "content": "Hello! I'm fine."}, "finish_reason": "stop"}
        ],
        "model": "gpt-4",
    }
    return backend


@pytest.fixture
def mock_shield_backend() -> AsyncMock:
    backend = AsyncMock(spec=ShieldBackend)
    backend.send.return_value = {
        "response": "Processed securely via shield.",
        "judge_verdict": "ALLOW",
        "model_used": "llama-3",
    }
    return backend


@pytest.fixture
def router_service(mock_normal_backend: AsyncMock, mock_shield_backend: AsyncMock) -> RouterService:
    return RouterService(
        normal_backend=mock_normal_backend,
        shield_backend=mock_shield_backend,
    )


@pytest.fixture
def sample_request() -> ChatRequest:
    return ChatRequest(
        messages=[Message(role="user", content="Hello")],
    )


@pytest.fixture
def normal_decision() -> PolicyDecision:
    return PolicyDecision(
        route=Route.NORMAL,
        reason="Request classified as NORMAL",
        classification_result=ClassificationResult(
            classification=Classification.NORMAL,
            confidence=0.0,
            reasons=[],
            matched_rules=[],
        ),
    )


@pytest.fixture
def shield_decision() -> PolicyDecision:
    return PolicyDecision(
        route=Route.SHIELD,
        reason="Request classified as RESTRICTED",
        classification_result=ClassificationResult(
            classification=Classification.RESTRICTED,
            confidence=0.9,
            reasons=["jailbreak_detected"],
            matched_rules=[],
        ),
    )


class TestNormalRouting:
    """Test normal flow routing."""

    @pytest.mark.asyncio
    async def test_normal_route_calls_normal_backend(
        self,
        router_service: RouterService,
        sample_request: ChatRequest,
        normal_decision: PolicyDecision,
        mock_normal_backend: AsyncMock,
    ) -> None:
        response = await router_service.route(normal_decision, sample_request)
        mock_normal_backend.send.assert_called_once()
        assert response.route_taken == "NORMAL"

    @pytest.mark.asyncio
    async def test_normal_route_returns_content(
        self,
        router_service: RouterService,
        sample_request: ChatRequest,
        normal_decision: PolicyDecision,
    ) -> None:
        response = await router_service.route(normal_decision, sample_request)
        assert len(response.choices) > 0
        assert response.choices[0].message.content == "Hello! I'm fine."


class TestShieldRouting:
    """Test shield flow routing."""

    @pytest.mark.asyncio
    async def test_shield_route_calls_shield_backend(
        self,
        router_service: RouterService,
        sample_request: ChatRequest,
        shield_decision: PolicyDecision,
        mock_shield_backend: AsyncMock,
    ) -> None:
        response = await router_service.route(shield_decision, sample_request)
        mock_shield_backend.send.assert_called_once()
        assert response.route_taken == "SHIELD"

    @pytest.mark.asyncio
    async def test_shield_route_returns_content(
        self,
        router_service: RouterService,
        sample_request: ChatRequest,
        shield_decision: PolicyDecision,
    ) -> None:
        response = await router_service.route(shield_decision, sample_request)
        assert len(response.choices) > 0
        assert response.choices[0].message.content == "Processed securely via shield."


class TestShieldFailClosed:
    """Test fail-closed behavior — SR-3."""

    @pytest.mark.asyncio
    async def test_shield_failure_raises_error(
        self,
        router_service: RouterService,
        sample_request: ChatRequest,
        shield_decision: PolicyDecision,
        mock_shield_backend: AsyncMock,
    ) -> None:
        """Shield failure must raise error, NOT fall back to cloud."""
        mock_shield_backend.send.side_effect = ShieldUnavailableError("Shield is down")

        with pytest.raises(ShieldUnavailableError):
            await router_service.route(shield_decision, sample_request)

    @pytest.mark.asyncio
    async def test_shield_failure_no_normal_fallback(
        self,
        router_service: RouterService,
        sample_request: ChatRequest,
        shield_decision: PolicyDecision,
        mock_normal_backend: AsyncMock,
        mock_shield_backend: AsyncMock,
    ) -> None:
        """When shield fails, normal backend must NOT be called."""
        mock_shield_backend.send.side_effect = ShieldUnavailableError("Shield is down")

        with pytest.raises(ShieldUnavailableError):
            await router_service.route(shield_decision, sample_request)

        # Normal backend must NOT have been called (no cloud fallback)
        mock_normal_backend.send.assert_not_called()
