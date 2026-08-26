"""
Multi-Axis Threat Correlation Engine.

Inspired by Cisco DefenseClaw Lethal Trifecta / Risk Axes paradigm:
Correlates abstract risk axes across the request lifecycle:
- INGRESS_UNTRUSTED      (Adversarial delimiters, instruction overrides, persona switches)
- SENSITIVE_ACCESS       (Targeting system prompts, credentials, API keys, database schemas)
- EXTERNAL_EGRESS        (Requests destined for external systems, scans, or public networks)
- OBFUSCATED_CONTENT     (High-entropy chunks, homoglyphs, script-tampering, base64)
- AUTHORIZATION_UNCERTAIN (Spoofed admin tokens, role impersonation without verification)

When 2 or more axes converge, issues abstract correlation evidence to the Risk Evidence vector.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CorrelationEvidence:
    """Structured correlation finding across abstract risk axes."""
    correlation: str
    score: float
    axes: list[str]
    description: str


class RiskAxesCorrelator:
    """Correlates abstract risk axes to detect multi-stage or composite attack patterns."""

    AXIS_INGRESS_UNTRUSTED = "INGRESS_UNTRUSTED"
    AXIS_SENSITIVE_ACCESS = "SENSITIVE_ACCESS"
    AXIS_EXTERNAL_EGRESS = "EXTERNAL_EGRESS"
    AXIS_OBFUSCATED_CONTENT = "OBFUSCATED_CONTENT"
    AXIS_AUTHORIZATION_UNCERTAIN = "AUTHORIZATION_UNCERTAIN"

    @classmethod
    def correlate(
        cls,
        rule_reasons: list[str],
        specialized_reasons: list[str],
        semantic_categories: dict[str, float],
        caller_metadata: dict[str, Any] | None = None,
    ) -> list[CorrelationEvidence]:
        """
        Evaluate correlation across abstract risk axes.
        Returns a list of structured CorrelationEvidence findings.
        """
        all_reasons = set(rule_reasons + specialized_reasons)
        all_reasons_str = " ".join(all_reasons).lower()
        active_axes: list[str] = []

        # 1. Ingress Untrusted Axis
        if any(k in all_reasons_str for k in ("instruction_override", "jailbreak", "role_injection", "structural_delimiters", "persona_hijack", "sequence")):
            active_axes.append(cls.AXIS_INGRESS_UNTRUSTED)

        # 2. Sensitive Access Axis
        if (
            any(k in all_reasons_str for k in ("system_prompt", "credential", "api_key", "password", "tool_schema", "pii", "database", "secret", "dlp_confirmed")) or
            semantic_categories.get("privacy", 0.0) >= 0.50 or
            semantic_categories.get("business_confidential", 0.0) >= 0.50
        ):
            active_axes.append(cls.AXIS_SENSITIVE_ACCESS)

        # 3. External Egress Axis
        if any(k in all_reasons_str for k in ("cyber_attack", "malware", "scan_breach")):
            active_axes.append(cls.AXIS_EXTERNAL_EGRESS)

        # 4. Obfuscated Content Axis
        if any(k in all_reasons_str for k in ("obfuscation", "mixed_script", "homoglyph", "high_entropy")):
            active_axes.append(cls.AXIS_OBFUSCATED_CONTENT)

        # 5. Authorization Uncertain Axis
        if any(k in all_reasons_str for k in ("role_spoofing", "authority_impersonation", "auth_spoof")):
            active_axes.append(cls.AXIS_AUTHORIZATION_UNCERTAIN)

        correlations: list[CorrelationEvidence] = []

        # Multi-Axis Convergence Checks
        has_ingress = cls.AXIS_INGRESS_UNTRUSTED in active_axes
        has_sensitive = cls.AXIS_SENSITIVE_ACCESS in active_axes
        has_egress = cls.AXIS_EXTERNAL_EGRESS in active_axes

        if has_ingress and has_sensitive and has_egress:
            correlations.append(
                CorrelationEvidence(
                    correlation="critical_exfiltration_trifecta",
                    score=0.98,
                    axes=[cls.AXIS_INGRESS_UNTRUSTED, cls.AXIS_SENSITIVE_ACCESS, cls.AXIS_EXTERNAL_EGRESS],
                    description="Convergence of untrusted override, sensitive asset targeting, and external egress"
                )
            )
        elif has_ingress and has_sensitive:
            correlations.append(
                CorrelationEvidence(
                    correlation="sensitive_extraction_convergence",
                    score=0.92,
                    axes=[cls.AXIS_INGRESS_UNTRUSTED, cls.AXIS_SENSITIVE_ACCESS],
                    description="Convergence of untrusted prompt manipulation and sensitive target harvesting"
                )
            )
        elif has_ingress and has_egress:
            correlations.append(
                CorrelationEvidence(
                    correlation="unauthorized_remote_action_convergence",
                    score=0.90,
                    axes=[cls.AXIS_INGRESS_UNTRUSTED, cls.AXIS_EXTERNAL_EGRESS],
                    description="Convergence of override framing and external target penetration"
                )
            )

        return correlations
