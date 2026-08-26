"""
Unit Tests for Phase 4: Policy Engine Integration, Gray-Zone Gating, and Fail-Closed Routing.
"""

import pytest
from classifier.models import Classification, ClassificationResult, RuleMatch, RuleType, Severity
from classifier.guard_models import GuardEvidence, GuardVerdict
from policy.engine import PolicyEngine
from policy.models import Route


@pytest.fixture
def policy_engine():
    return PolicyEngine()


def test_policy_deterministic_dlp_routes_to_shield(policy_engine):
    # Rule match for credit card
    rule = RuleMatch(
        rule_name="DLP_CREDIT_CARD_LEAK",
        pattern_matched=r"\b(?:\d[ -]*?){13,16}\b",
        severity=Severity.HIGH,
        match_type=RuleType.REGEX,
    )
    result = ClassificationResult(
        classification=Classification.RESTRICTED,
        confidence=0.95,
        risk_score=0.95,
        categories={"privacy": 0.95},
        matched_rules=[rule],
    )
    decision = policy_engine.evaluate(result)
    assert decision.route == Route.SHIELD
    assert "POL-006" in decision.reason or "privacy" in decision.reason


def test_policy_guard_unsafe_routes_to_shield(policy_engine):
    guard_ev = GuardEvidence(
        verdict=GuardVerdict.UNSAFE,
        raw_output="unsafe\nS2",
        raw_categories=["S2"],
        canonical_categories=["non_violent_crimes"],
        confidence=0.95,
    )
    result = ClassificationResult(
        classification=Classification.RESTRICTED,
        confidence=0.95,
        risk_score=0.95,
        categories={"harmful": 0.95},
        reasons=["neural_guard_unsafe:S2"],
    )
    decision = policy_engine.evaluate(result, guard_evidence=guard_ev)
    assert decision.route == Route.SHIELD
    assert "POL-GUARD-001" in decision.reason


def test_policy_guard_unavailable_fails_closed_to_shield(policy_engine):
    guard_ev = GuardEvidence(
        verdict=GuardVerdict.UNAVAILABLE,
        raw_output="connection timeout",
        status="service_unavailable",
    )
    result = ClassificationResult(
        classification=Classification.RESTRICTED,
        confidence=0.0,
        risk_score=0.0,
        reasons=["neural_guard_unavailable_fail_closed"],
    )
    decision = policy_engine.evaluate(result, guard_evidence=guard_ev)
    assert decision.route == Route.SHIELD
    assert "POL-GUARD-002" in decision.reason


def test_policy_guard_safe_and_clean_routes_to_normal(policy_engine):
    guard_ev = GuardEvidence(
        verdict=GuardVerdict.SAFE,
        raw_output="safe",
        confidence=1.0,
    )
    result = ClassificationResult(
        classification=Classification.NORMAL,
        confidence=0.05,
        risk_score=0.05,
        categories={"security": 0.05, "privacy": 0.0, "harmful": 0.0},
        reasons=[],
    )
    decision = policy_engine.evaluate(result, guard_evidence=guard_ev)
    assert decision.route == Route.NORMAL
    assert "NORMAL" in decision.reason
