"""
Policy Engine tests — PRD §6.5.

Tests:
- RESTRICTED → SHIELD route
- NORMAL → NORMAL route
- Error/unknown → SHIELD (fail closed per SR-3)
"""

from __future__ import annotations

import pytest

from classifier.models import Classification, ClassificationResult
from policy.engine import PolicyEngine
from policy.models import Route


@pytest.fixture
def policy_engine() -> PolicyEngine:
    return PolicyEngine()


def _make_result(
    classification: Classification,
    confidence: float = 0.5,
    reasons: list[str] | None = None,
) -> ClassificationResult:
    return ClassificationResult(
        classification=classification,
        confidence=confidence,
        reasons=reasons or [],
        matched_rules=[],
    )


class TestPolicyDecisions:
    """Test correct routing based on classification."""

    def test_restricted_routes_to_shield(self, policy_engine: PolicyEngine) -> None:
        result = _make_result(Classification.RESTRICTED, 0.9, ["jailbreak_detected"])
        decision = policy_engine.evaluate(result)
        assert decision.route == Route.SHIELD

    def test_normal_routes_to_normal(self, policy_engine: PolicyEngine) -> None:
        result = _make_result(Classification.NORMAL, 0.1)
        decision = policy_engine.evaluate(result)
        assert decision.route == Route.NORMAL

    def test_restricted_includes_reason(self, policy_engine: PolicyEngine) -> None:
        result = _make_result(Classification.RESTRICTED, 0.95, ["rule_1", "rule_2"])
        decision = policy_engine.evaluate(result)
        assert "RESTRICTED" in decision.reason
        assert decision.classification_result is not None

    def test_normal_includes_reason(self, policy_engine: PolicyEngine) -> None:
        result = _make_result(Classification.NORMAL, 0.0)
        decision = policy_engine.evaluate(result)
        assert "NORMAL" in decision.reason


class TestFailClosed:
    """Test fail-closed behavior — SR-3."""

    def test_restricted_low_confidence_still_shield(self, policy_engine: PolicyEngine) -> None:
        """Even RESTRICTED with low confidence goes to SHIELD."""
        result = _make_result(Classification.RESTRICTED, 0.1)
        decision = policy_engine.evaluate(result)
        assert decision.route == Route.SHIELD

    def test_decision_preserves_classification(self, policy_engine: PolicyEngine) -> None:
        result = _make_result(Classification.RESTRICTED, 0.9, ["test_rule"])
        decision = policy_engine.evaluate(result)
        assert decision.classification_result == result


class TestDeclarativePolicies:
    """Test evaluating external declarative policies from policy/policies.json."""

    def test_business_confidential_policy_triggers_shield(self, policy_engine: PolicyEngine) -> None:
        result = ClassificationResult(
            classification=Classification.RESTRICTED,
            confidence=0.80,
            risk_score=0.80,
            categories={"business_confidential": 0.85, "security": 0.0},
            reasons=["pre_release_financial_data"],
            matched_rules=[],
        )
        decision = policy_engine.evaluate(result)
        assert decision.route == Route.SHIELD
        assert "POL-003" in decision.reason

    def test_strictly_confidential_metadata_policy(self, policy_engine: PolicyEngine) -> None:
        result = ClassificationResult(
            classification=Classification.NORMAL,
            confidence=0.10,
            risk_score=0.10,
            categories={"security": 0.0},
            reasons=[],
            matched_rules=[],
        )
        metadata = {"project_sensitivity": "strictly_confidential"}
        decision = policy_engine.evaluate(result, metadata=metadata)
        assert decision.route == Route.SHIELD
        assert "POL-008" in decision.reason

    def test_guest_role_stricter_threshold(self, policy_engine: PolicyEngine) -> None:
        result = ClassificationResult(
            classification=Classification.NORMAL,
            confidence=0.35,
            risk_score=0.35,
            categories={"security": 0.35},
            reasons=[],
            matched_rules=[],
        )
        # For a standard employee, 0.35 is below default 0.50 -> NORMAL
        employee_dec = policy_engine.evaluate(result, metadata={"user_role": "employee"})
        assert employee_dec.route == Route.NORMAL

        # For an untrusted guest, 0.35 triggers POL-009 (threshold 0.30) -> SHIELD
        guest_dec = policy_engine.evaluate(result, metadata={"user_role": "guest"})
        assert guest_dec.route == Route.SHIELD
        assert "POL-009" in guest_dec.reason

    def test_medical_privacy_role_abac(self, policy_engine: PolicyEngine) -> None:
        result = ClassificationResult(
            classification=Classification.RESTRICTED,
            confidence=0.75,
            risk_score=0.75,
            categories={"medical": 0.80},
            reasons=["patient_medical_history"],
            matched_rules=[],
        )
        # Authorized doctor -> NORMAL
        doctor_dec = policy_engine.evaluate(result, metadata={"user_role": "doctor"})
        assert doctor_dec.route == Route.NORMAL

        # External user -> SHIELD (POL-005)
        external_dec = policy_engine.evaluate(result, metadata={"user_role": "external_guest"})
        assert external_dec.route == Route.SHIELD
        assert "POL-005" in external_dec.reason

