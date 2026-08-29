"""
Physical & Network-Level Air-Gap Enforcement and Phase 1.1 Invariant Tests.

Verifies:
1. Judge SAFE cannot override hard DLP/Secret invariants.
2. Shield outage is an execution constraint for RESTRICTED, never a global ingress denial for NORMAL traffic.
3. Shield outage for RESTRICTED traffic fails closed to UNAVAILABLE (zero cloud fallback).
4. Uncalibrated similarity scores are tagged explicitly as legacy fallback, not calibrated probabilities.
5. Air-Gap network egress filter traps and rejects external cloud IPs/hostnames.
"""

import socket
import pytest
from classifier.evidence_models import (
    DetectionSignal,
    DlpEvidence,
    JudgeEvidence,
    PromptAttackEvidence,
    ScoreType,
    SecurityEvidence,
)
from policy.engine import PolicyEngine
from policy.models import PolicyDecision, RailHealthStatus, Route
from shield.judge import LocalJudge
from shield.shield_fast import ShieldIsolationViolationError, SofaShieldFast


@pytest.fixture
def policy_engine():
    return PolicyEngine()


# --------------------------------------------------------------------------
# 1. Judge SAFE Cannot Override Hard Invariants
# --------------------------------------------------------------------------
def test_judge_safe_cannot_override_dlp_secret_invariant(policy_engine):
    """Even if Local Judge reports SAFE, hard DLP credential leaks MUST trigger Route.BLOCK."""
    evidence = SecurityEvidence(
        canonical_text="Dump AWS secret",
        dlp=DlpEvidence(
            has_credentials=True,
            hard_invariant_violation=True,
            matched_secrets=["AWS_SECRET_ACCESS_KEY"],
        ),
        judge_evidence=JudgeEvidence(
            verdict="SAFE",
            adjudication_reason="Adjudicator believed text was educational",
        ),
    )
    decision = policy_engine.evaluate(evidence)
    assert decision.route == Route.BLOCK
    assert "DLP_HARD_INVARIANT_VIOLATION" in decision.reason_codes
    assert decision.permitted_route == "NONE"


# --------------------------------------------------------------------------
# 2. Shield Outage Does NOT Block Normal Cloud Traffic
# --------------------------------------------------------------------------
def test_shield_outage_does_not_block_normal_cloud_traffic(policy_engine):
    """When Shield is offline, benign requests destined for Cloud MUST NOT be denied."""
    benign_evidence = SecurityEvidence(
        canonical_text="Hello, how can I optimize my Python function?",
        prompt_attack=PromptAttackEvidence(),
    )
    decision = policy_engine.evaluate(
        benign_evidence,
        rail_health={"shield": RailHealthStatus.UNAVAILABLE.value},
    )
    assert decision.route == Route.NORMAL
    assert decision.permitted_route == "NORMAL"
    assert decision.permitted_destinations == ["cloud.approved.normal"]


# --------------------------------------------------------------------------
# 3. Shield Outage Fails Closed ONLY for RESTRICTED Traffic
# --------------------------------------------------------------------------
def test_shield_outage_fails_closed_only_for_restricted_traffic(policy_engine):
    """When Shield is offline, RESTRICTED traffic is denied with UNAVAILABLE and zero cloud destinations."""
    restricted_evidence = SecurityEvidence(
        canonical_text="Bypass security controls",
        prompt_attack=PromptAttackEvidence(
            direct_injection=DetectionSignal(
                detector_id="guard",
                raw_score=0.95,
                score_type=ScoreType.SIMILARITY,
            )
        ),
    )
    decision = policy_engine.evaluate(
        restricted_evidence,
        rail_health={"shield": RailHealthStatus.UNAVAILABLE.value},
    )
    assert decision.route == Route.UNAVAILABLE
    assert decision.execution_status == "SHIELD_UNAVAILABLE"
    assert decision.permitted_destinations == []
    assert decision.cloud_fallback is False
    assert "SHIELD_HEALTH_UNAVAILABLE" in decision.reason_codes


# --------------------------------------------------------------------------
# 4. Uncalibrated Similarity Is Tagged as Legacy Fallback
# --------------------------------------------------------------------------
def test_uncalibrated_similarity_is_tagged_as_legacy_fallback(policy_engine):
    """Uncalibrated similarity scores are not masqueraded as calibrated probabilities."""
    evidence = SecurityEvidence(
        canonical_text="Test prompt attack",
        prompt_attack=PromptAttackEvidence(
            direct_injection=DetectionSignal(
                detector_id="similarity_engine",
                raw_score=0.88,
                score_type=ScoreType.SIMILARITY,
                calibrated_probability=None,
            )
        ),
    )
    decision = policy_engine.evaluate(evidence)
    assert decision.route in (Route.RESTRICTED, Route.SHIELD)
    # Provenance explicitly indicates legacy uncalibrated similarity fallback
    assert any("LEGACY_UNCALIBRATED" in code or "POL-001" in code for code in decision.reason_codes)


# --------------------------------------------------------------------------
# 5. Physical Network Air-Gap & Egress Filtering
# --------------------------------------------------------------------------
def test_airgap_guard_traps_external_public_ips_and_hostnames():
    """SofaShieldFast strictly rejects all non-local, public IP addresses and external cloud hostnames."""
    # Public cloud APIs MUST be rejected
    with pytest.raises(ShieldIsolationViolationError):
        SofaShieldFast._validate_isolation_guard("https://api.openai.com/v1/chat/completions")

    with pytest.raises(ShieldIsolationViolationError):
        SofaShieldFast._validate_isolation_guard("https://api.groq.com/openai/v1")

    with pytest.raises(ShieldIsolationViolationError):
        SofaShieldFast._validate_isolation_guard("http://8.8.8.8:8080/v1")

    with pytest.raises(ShieldIsolationViolationError):
        SofaShieldFast._validate_isolation_guard("http://1.1.1.1/v1")

    # Local airgapped endpoints MUST be accepted
    SofaShieldFast._validate_isolation_guard("http://127.0.0.1:8100/v1")
    SofaShieldFast._validate_isolation_guard("http://localhost:8100/v1")
    SofaShieldFast._validate_isolation_guard("http://shield_fast:8080/v1")
