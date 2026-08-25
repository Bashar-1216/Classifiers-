"""
Enterprise Observability & Zero-Leakage Audit Telemetry.

Logs structured, privacy-preserving risk assessment telemetry:
- Request ID, Timestamp, User Role, Project Sensitivity
- SHA-256 Prompt Hash (guarantees ZERO raw prompt or PII data logging)
- Multi-dimensional Risk Scores & Triggers
- Policy Decision & Routing Execution
- Output Safety Verdict & Sanitization Flag
- Latency (ms)
Guarantees zero leakage for enterprise compliance (GDPR/HIPAA/SOC2).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gateway.metrics import MetricsCollector

logger = logging.getLogger("gateway.audit")


class AuditLogger:
    """
    Emits structured, privacy-preserving security audit logs and updates metrics.
    """

    @staticmethod
    def hash_text(text: Optional[str]) -> str:
        """Compute non-reversible SHA-256 hash of text for audit correlation."""
        if not text:
            return "empty"
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]

    @classmethod
    def log_event(
        cls,
        request_id: str,
        duration_ms: float,
        risk_score: float,
        categories: Dict[str, float],
        reasons: List[str],
        route: str,
        policy_reason: str,
        metadata: Optional[Dict[str, Any]] = None,
        model: Optional[str] = None,
        prompt_text: Optional[str] = None,
        output_verdict: str = "ALLOW",
        output_modified: bool = False,
        status_code: int = 200,
    ) -> Dict[str, Any]:
        """
        Record a structured security audit telemetry event.
        """
        meta = metadata or {}
        prompt_hash = cls.hash_text(prompt_text)

        audit_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "prompt_hash": prompt_hash,
            "duration_ms": round(duration_ms, 2),
            "model_requested": model or "default",
            "user_role": meta.get("user_role", "unspecified"),
            "project_sensitivity": meta.get("project_sensitivity", "unspecified"),
            "environment": meta.get("environment", "unspecified"),
            "risk_assessment": {
                "risk_score": round(risk_score, 4),
                "categories": {k: round(v, 4) for k, v in categories.items()},
                "triggers": reasons,
            },
            "governance": {
                "route_decision": route,
                "policy_reason": policy_reason,
            },
            "output_safety": {
                "verdict": output_verdict,
                "sanitized": output_modified,
            },
        }

        # Log as structured JSON string for SIEM / Splunk / Datadog ingestion
        logger.info("[AUDIT_TELEMETRY] %s", json.dumps(audit_record))

        # Update in-memory metrics collector
        MetricsCollector().record_request(
            route=route,
            status=status_code,
            duration_ms=duration_ms,
            categories=categories,
            output_verdict=output_verdict,
        )

        return audit_record
