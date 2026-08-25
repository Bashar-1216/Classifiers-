"""
Automated Pytest Suite for 25 Red Team Test Vectors.
Ensures continuous regression testing across all risk categories and languages.
"""

from __future__ import annotations

import pytest
from classifier.service import ClassifierService
from policy.engine import PolicyEngine
from scripts.run_red_team import RED_TEAM_SUITES, TestCase


@pytest.fixture(scope="module")
def classifier_service() -> ClassifierService:
    return ClassifierService(rules_dir="./rules")


@pytest.fixture(scope="module")
def policy_engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.mark.parametrize("test_case", RED_TEAM_SUITES, ids=lambda tc: f"{tc.test_id}_{tc.suite_name}")
def test_red_team_case(
    test_case: TestCase,
    classifier_service: ClassifierService,
    policy_engine: PolicyEngine,
) -> None:
    """Execute each individual Red Team test case against the classifier and policy engine."""
    classification_result = classifier_service.classify(
        text=test_case.prompt,
        messages=test_case.messages,
        metadata=test_case.metadata,
    )
    decision = policy_engine.evaluate(
        classification_result=classification_result,
        metadata=test_case.metadata,
    )
    assert decision.route.value == test_case.expected_route, (
        f"[{test_case.test_id}] Failed for '{test_case.prompt}'. "
        f"Expected {test_case.expected_route} but got {decision.route.value}. "
        f"Reason: {decision.reason} | Categories: {classification_result.categories}"
    )
