"""
Comprehensive Audit & Integrity Invariant Tests for Phase 1 Sealing.

Verifies the 4 critical security audit dimensions:
1. Decision Integrity & Cryptographic Tamper-Proofing
2. Rail Health Semantics & Fail-Closed Invariants
3. Strict Destination Allowlisting
4. Local Judge Permissions & Air-Gap Isolation
"""

import time
import pytest
from classifier.evidence_models import (
    JudgeEvidence,
    PromptAttackEvidence,
    DetectionSignal,
    ScoreType,
    SecurityEvidence,
)
from policy.engine import PolicyEngine
from policy.models import PolicyDecision, RailHealthStatus, Route
from router.normal_backend import NormalBackend
from router.service import RouterService
from router.shield_backend import ShieldBackend, ShieldUnavailableError
from shield.judge import LocalJudge
from schemas import ChatRequest, Message


@pytest.fixture
def policy_engine():
    return PolicyEngine()


@pytest.fixture
def router_service():
    normal = NormalBackend(backend_url="http://mock-cloud/v1")
    shield = ShieldBackend(shield_url="http://mock-shield/v1")
    return RouterService(normal_backend=normal, shield_backend=shield)


# --------------------------------------------------------------------------
# 1. Decision Integrity & Tamper-Proofing
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_router_rejects_expired_policy_decision(router_service):
    """PEP Router rejects decisions that have exceeded their TTL."""
    req = ChatRequest(request_id="req-1234", messages=[Message(role="user", content="test")])
    decision = PolicyDecision(
        request_id="req-1234",
        route=Route.NORMAL,
        reason="normal allow",
        permitted_route="NORMAL",
        permitted_destinations=["cloud.approved.normal"],
        issued_at=time.time() - 100.0,
        expires_at=time.time() - 10.0,  # Expired
    )
    decision.sign()

    with pytest.raises(ShieldUnavailableError) as exc_info:
        await router_service.route(decision, req)

    assert "EXPIRED_DECISION" in str(exc_info.value)


@pytest.mark.asyncio
async def test_router_rejects_restricted_decision_with_cloud_route(router_service):
    """PEP Router rejects RESTRICTED decisions listing cloud destinations."""
    req = ChatRequest(request_id="req-1234", messages=[Message(role="user", content="test")])
    decision = PolicyDecision(
        request_id="req-1234",
        route=Route.RESTRICTED,
        reason="restricted",
        permitted_route="SHIELD",
        permitted_destinations=["https://api.groq.com/openai/v1"],  # Illegal Cloud Destination
        cloud_fallback=False,
    )
    decision.sign()

    with pytest.raises(ShieldUnavailableError) as exc_info:
        await router_service.route(decision, req)

    assert "ILLEGAL_DESTINATION" in str(exc_info.value)


@pytest.mark.asyncio
async def test_router_rejects_restricted_decision_with_cloud_fallback_enabled(router_service):
    """PEP Router rejects RESTRICTED decisions with cloud_fallback=True."""
    req = ChatRequest(request_id="req-1234", messages=[Message(role="user", content="test")])
    decision = PolicyDecision(
        request_id="req-1234",
        route=Route.RESTRICTED,
        reason="restricted",
        permitted_route="SHIELD",
        permitted_destinations=["shield.internal.local"],
        cloud_fallback=True,  # Illegal Invariant
    )
    decision.sign()

    with pytest.raises(ShieldUnavailableError) as exc_info:
        await router_service.route(decision, req)

    assert "ILLEGAL_INVARIANT" in str(exc_info.value)


@pytest.mark.asyncio
async def test_router_rejects_unsigned_or_untrusted_decision(router_service):
    """PEP Router rejects decisions with invalid/forged signatures."""
    req = ChatRequest(request_id="req-1234", messages=[Message(role="user", content="test")])
    decision = PolicyDecision(
        request_id="req-1234",
        route=Route.NORMAL,
        reason="normal",
        permitted_route="NORMAL",
        permitted_destinations=["cloud.approved.normal"],
        signature="forged_signature_000000000000",
    )

    with pytest.raises(ShieldUnavailableError) as exc_info:
        await router_service.route(decision, req)

    assert "MUTATED_DECISION" in str(exc_info.value)


@pytest.mark.asyncio
async def test_router_rejects_request_decision_id_mismatch(router_service):
    """PEP Router rejects decisions bound to a different request_id."""
    req = ChatRequest(request_id="req-ATTACKER-999", messages=[Message(role="user", content="test")])
    decision = PolicyDecision(
        request_id="req-VICTIM-111",
        route=Route.NORMAL,
        reason="normal",
        permitted_route="NORMAL",
        permitted_destinations=["cloud.approved.normal"],
    )
    decision.sign()

    with pytest.raises(ShieldUnavailableError) as exc_info:
        await router_service.route(decision, req)

    assert "REQUEST_MISMATCH" in str(exc_info.value)


@pytest.mark.asyncio
async def test_router_rejects_mutated_policy_decision(router_service):
    """PEP Router rejects decisions whose payload fields were mutated after signing."""
    req = ChatRequest(request_id="req-1234", messages=[Message(role="user", content="test")])
    decision = PolicyDecision(
        request_id="req-1234",
        route=Route.RESTRICTED,
        reason="restricted",
        permitted_route="SHIELD",
        permitted_destinations=["shield.internal.local"],
        cloud_fallback=False,
    )
    decision.sign()

    # Attacker mutates route from RESTRICTED to NORMAL in memory
    decision.route = Route.NORMAL
    decision.permitted_route = "NORMAL"

    with pytest.raises(ShieldUnavailableError) as exc_info:
        await router_service.route(decision, req)

    assert "MUTATED_DECISION" in str(exc_info.value)


# --------------------------------------------------------------------------
# 2. Rail Health Semantics & Fail-Closed Invariants
# --------------------------------------------------------------------------
def test_required_rail_unavailable_never_defaults_to_cloud(policy_engine):
    """When a required security rail is degraded/unavailable, PDP NEVER routes to cloud."""
    evidence = SecurityEvidence(canonical_text="sample benign query")

    # Prompt attack rail timed out
    decision = policy_engine.evaluate(
        evidence,
        rail_health={"prompt_attack": RailHealthStatus.TIMEOUT.value},
    )
    assert decision.route in (Route.RESTRICTED, Route.SHIELD)
    assert decision.permitted_route == "SHIELD"
    assert decision.cloud_fallback is False
    assert "PROMPT_ATTACK_RAIL_TIMEOUT_FAIL_CLOSED" in decision.reason_codes


def test_dlp_rail_unavailable_blocks_or_restricts(policy_engine):
    """When DLP rail is unavailable, PDP blocks to prevent uninspected sensitive egress."""
    evidence = SecurityEvidence(canonical_text="sample query")
    decision = policy_engine.evaluate(
        evidence,
        rail_health={"dlp": RailHealthStatus.UNAVAILABLE.value},
    )
    assert decision.route == Route.BLOCK
    assert decision.permitted_route == "NONE"
    assert "DLP_RAIL_UNAVAILABLE_FAIL_CLOSED" in decision.reason_codes


def test_local_judge_timeout_never_routes_normal(policy_engine):
    """When Local Judge times out or fails, PDP re-evaluation fails closed to Shield (NEVER auto-NORMAL)."""
    evidence = SecurityEvidence(
        canonical_text="ambiguous query",
        prompt_attack=PromptAttackEvidence(
            direct_injection=DetectionSignal(detector_id="guard", raw_score=0.45, score_type=ScoreType.SIMILARITY)
        ),
        judge_evidence=JudgeEvidence(
            verdict="ERROR",
            adjudication_reason="Local judge timed out after 10000ms",
        ),
    )
    decision = policy_engine.evaluate(evidence)
    assert decision.route in (Route.RESTRICTED, Route.SHIELD)
    assert decision.permitted_route == "SHIELD"
    assert decision.cloud_fallback is False
    assert "JUDGE_UNCERTAIN_FAIL_CLOSED" in decision.reason_codes


# --------------------------------------------------------------------------
# 3. Strict Destination Allowlisting
# --------------------------------------------------------------------------
def test_destination_allowlist_enforcement(policy_engine):
    """PDP strictly attaches closed destination allowlists to decisions."""
    # 1. Normal Allow
    evidence_normal = SecurityEvidence(canonical_text="Hello world")
    decision_normal = policy_engine.evaluate(evidence_normal)
    assert decision_normal.permitted_destinations == ["cloud.approved.normal"]

    # 2. Restricted Shield
    evidence_restricted = SecurityEvidence(
        canonical_text="attack",
        prompt_attack=PromptAttackEvidence(
            direct_injection=DetectionSignal(detector_id="guard", raw_score=0.90, score_type=ScoreType.SIMILARITY)
        ),
    )
    decision_restricted = policy_engine.evaluate(evidence_restricted)
    assert decision_restricted.permitted_destinations == ["shield.internal.local"]


# --------------------------------------------------------------------------
# 4. Local Judge Permissions & Air-Gap Isolation
# --------------------------------------------------------------------------
def test_judge_has_no_cloud_connector():
    """LocalJudge is an air-gapped component with zero cloud connectors or network egress handles."""
    judge = LocalJudge()
    assert not hasattr(judge, "cloud_client")
    assert not hasattr(judge, "normal_backend")
    assert not hasattr(judge, "api_key")
    assert not hasattr(judge, "network_socket")


def test_judge_cannot_invoke_router_or_tool_gateway():
    """LocalJudge cannot invoke routing or execute external tools; it emits JudgeEvidence ONLY."""
    judge = LocalJudge()
    assert not hasattr(judge, "router")
    assert not hasattr(judge, "tool_gateway")

    evidence = judge.adjudicate("What is public key cryptography?")
    assert isinstance(evidence, JudgeEvidence)
    assert not hasattr(evidence, "permitted_route")
    assert not hasattr(evidence, "route")
