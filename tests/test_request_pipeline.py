"""
Unit Tests for RequestPipeline: Verifies the mandatory classify -> policy -> route sequence.
"""

from unittest.mock import AsyncMock, MagicMock
import pytest

from classifier.models import Classification, ClassificationResult
from policy.models import PolicyDecision, Route
from router.request_pipeline import RequestPipeline
from router.shield_backend import ShieldUnavailableError
from schemas import ChatChoice, ChatRequest, ChatResponse, Message


@pytest.mark.asyncio
async def test_pipeline_mandatory_order_classify_policy_route():
    """
    Verifies that RequestPipeline executes strictly:
      1. classifier.classify(...) with get_full_text, messages, metadata
      2. policy_engine.evaluate(classification, metadata)
      3. router.route(decision, request)
    in that exact sequential order.
    """
    call_order = []

    mock_classifier = MagicMock()
    mock_policy = MagicMock()
    mock_router = MagicMock()

    dummy_classification = ClassificationResult(
        classification=Classification.NORMAL,
        confidence=0.1,
        risk_score=0.1,
        reasons=[],
        categories={},
    )
    dummy_decision = PolicyDecision(
        route=Route.NORMAL,
        policy_id="POL-001",
        reason="Clean request",
        classification_result=dummy_classification,
    )
    dummy_response = ChatResponse(
        choices=[ChatChoice(message=Message(role="assistant", content="Hello world"))],
        route_taken="NORMAL",
    )

    def fake_classify(text, messages=None, metadata=None):
        call_order.append("classify")
        assert text == "Hello, please help me with code"
        assert len(messages) == 1
        assert messages[0]["content"] == "Hello, please help me with code"
        assert metadata == {"user_role": "developer"}
        return dummy_classification

    def fake_evaluate(classification, metadata=None):
        call_order.append("policy")
        assert classification == dummy_classification
        assert metadata == {"user_role": "developer"}
        return dummy_decision

    async def fake_route(decision, request):
        call_order.append("route")
        assert decision == dummy_decision
        return dummy_response

    mock_classifier.classify = MagicMock(side_effect=fake_classify)
    mock_policy.evaluate = MagicMock(side_effect=fake_evaluate)
    mock_router.route = AsyncMock(side_effect=fake_route)

    pipeline = RequestPipeline(
        classifier=mock_classifier,
        policy_engine=mock_policy,
        router=mock_router,
    )

    request = ChatRequest(
        messages=[Message(role="user", content="Hello, please help me with code")],
    )
    metadata = {"user_role": "developer"}

    response, decision = await pipeline.process(request, metadata=metadata)

    # 1. Strict sequence verification
    assert call_order == ["classify", "policy", "route"]

    # 2. Output verification
    assert response == dummy_response
    assert decision == dummy_decision


@pytest.mark.asyncio
async def test_pipeline_shield_fail_closed_zero_cloud_fallback():
    """
    Verifies that when a request is routed to SHIELD and Shield backend fails,
    RequestPipeline raises ShieldUnavailableError and never falls back to cloud.
    """
    mock_classifier = MagicMock()
    mock_policy = MagicMock()
    mock_router = MagicMock()

    dummy_classification = ClassificationResult(
        classification=Classification.RESTRICTED,
        confidence=0.9,
        risk_score=0.9,
        reasons=["credential_leak"],
    )
    dummy_decision = PolicyDecision(
        route=Route.SHIELD,
        policy_id="POL-006",
        reason="Credential leak protection",
        classification_result=dummy_classification,
    )

    mock_classifier.classify = MagicMock(return_value=dummy_classification)
    mock_policy.evaluate = MagicMock(return_value=dummy_decision)
    mock_router.route = AsyncMock(side_effect=ShieldUnavailableError("Local Shield Offline"))

    pipeline = RequestPipeline(
        classifier=mock_classifier,
        policy_engine=mock_policy,
        router=mock_router,
    )

    request = ChatRequest(
        messages=[Message(role="user", content="Here is my password: secret123")],
    )

    with pytest.raises(ShieldUnavailableError) as exc_info:
        await pipeline.process(request)

    assert "Local Shield Offline" in str(exc_info.value)
