"""
Tests for Enterprise Observability & Audit Telemetry module.
"""

from __future__ import annotations

import json
from gateway.observability import AuditLogger


class TestObservabilityAudit:
    """Test structured telemetry logging and zero-leakage compliance."""

    def test_audit_event_structure(self) -> None:
        record = AuditLogger.log_event(
            request_id="req-test-12345",
            duration_ms=25.4,
            risk_score=0.88,
            categories={"security": 0.88, "privacy": 0.0, "business_confidential": 0.0},
            reasons=["security_jailbreak_override"],
            route="SHIELD",
            policy_reason="RESTRICTED - Triggered Policy POL-001",
            metadata={"user_role": "contractor", "project_sensitivity": "confidential"},
            model="gemini-2.5-flash",
        )

        assert record["request_id"] == "req-test-12345"
        assert record["duration_ms"] == 25.4
        assert record["risk_assessment"]["risk_score"] == 0.88
        assert record["governance"]["route_decision"] == "SHIELD"
        assert record["user_role"] == "contractor"
        assert record["project_sensitivity"] == "confidential"

        # Verify it serializes to valid JSON without error
        json_str = json.dumps(record)
        assert "req-test-12345" in json_str

    def test_privacy_preserving_zero_prompt_leakage(self) -> None:
        """Verify that raw user text is never captured in audit telemetry."""
        record = AuditLogger.log_event(
            request_id="req-999",
            duration_ms=10.0,
            risk_score=0.1,
            categories={},
            reasons=[],
            route="NORMAL",
            policy_reason="NORMAL - Clean request",
        )

        # Audit schema should not contain raw prompt keys
        assert "prompt" not in record
        assert "message" not in record
        assert "content" not in record
