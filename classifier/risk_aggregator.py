"""
Risk Aggregator Engine — Multi-Dimensional Threat Synthesis.

Combines threat signals from:
1. Deterministic Rule Engine
2. Semantic Classifier (Intent & Nuance)
3. Specialized Detectors (PII, Jailbreak, Safety)
4. Context Analyzer (Multi-turn History)
5. Metadata Analyzer (Role, Environment, Sensitivity)

Uses weighted probabilistic union mathematics with role/metadata context sensitivity.
"""

from __future__ import annotations

import logging
from typing import Any

from classifier.models import Classification, ClassificationResult, RuleMatch

logger = logging.getLogger(__name__)


class RiskAggregator:
    """
    Synthesizes multi-source risk signals across Security, Privacy, Harmful, and Confidentiality.
    Applies weighted probabilistic union math and role-aware context calibration.
    """

    def __init__(self, confidence_threshold: float = 0.50) -> None:
        self.confidence_threshold = confidence_threshold

    def aggregate(
        self,
        rule_matches: list[RuleMatch],
        semantic_scores: dict[str, float],
        context_scores: dict[str, float],
        metadata_scores: dict[str, float],
        specialized_scores: dict[str, float] | None = None,
        caller_metadata: dict[str, Any] | None = None,
    ) -> ClassificationResult:
        """
        Aggregate all risk signals into a unified ClassificationResult.

        Args:
            rule_matches: Deterministic rules triggered.
            semantic_scores: Scores from Semantic Classifier.
            context_scores: Multi-turn trajectory anomalies.
            metadata_scores: Scores from Metadata Analyzer.
            specialized_scores: Scores from PII, Jailbreak, and Safety detectors.
            caller_metadata: Raw caller metadata for role-based weighting.

        Returns:
            ClassificationResult containing category breakdown, reasons, and overall risk score.
        """
        spec_scores = specialized_scores or {}
        meta_dict = caller_metadata or {}

        # Collect all individual risk factor names
        all_reasons: list[str] = [m.rule_name for m in rule_matches]
        all_reasons.extend(semantic_scores.keys())
        all_reasons.extend(spec_scores.keys())
        all_reasons.extend(context_scores.keys())
        all_reasons.extend(metadata_scores.keys())

        # Collect scores for probabilistic union
        scores: list[float] = [m.severity.score for m in rule_matches]
        scores.extend(semantic_scores.values())
        scores.extend(spec_scores.values())
        scores.extend(context_scores.values())
        scores.extend(metadata_scores.values())

        if not scores:
            return ClassificationResult(
                classification=Classification.NORMAL,
                confidence=0.0,
                risk_score=0.0,
                reasons=[],
                matched_rules=rule_matches,
            )

        # Probabilistic union formula: 1 - ∏(1 - s_i)
        complement_product = 1.0
        for score in scores:
            clamped = max(0.0, min(1.0, score))
            complement_product *= (1.0 - clamped)

        base_risk = 1.0 - complement_product

        # Role-based risk modifier:
        # Untrusted roles (guest, anonymous, untrusted_dmz) have amplified risk sensitivity
        user_role = str(meta_dict.get("user_role", "")).lower()
        env = str(meta_dict.get("environment", "")).lower()

        role_weight = 1.0
        if user_role in ("guest", "anonymous", "external") or env in ("public_internet", "untrusted_dmz"):
            role_weight = 1.15  # 15% sensitivity boost for untrusted callers
        elif user_role in ("admin", "security_auditor", "doctor"):
            role_weight = 1.0   # Baseline for authorized roles

        overall_confidence = round(min(1.0, base_risk * role_weight), 4)

        # Compute Category-Level Risk Scores
        category_breakdown: dict[str, float] = {
            "security": 0.0,
            "privacy": 0.0,
            "business_confidential": 0.0,
            "context": 0.0,
            "metadata": 0.0,
        }

        # 1. Map Rule Matches
        for m in rule_matches:
            name_lower = m.rule_name.lower()
            if any(k in name_lower for k in ["credential", "token", "password", "key", "secret"]):
                category_breakdown["privacy"] = max(category_breakdown["privacy"], m.severity.score)
            else:
                category_breakdown["security"] = max(category_breakdown["security"], m.severity.score)

        # 2. Map Semantic Scores
        for tag, score in semantic_scores.items():
            tag_lower = tag.lower()
            if "medical" in tag_lower or "health" in tag_lower:
                category_breakdown["medical"] = max(category_breakdown.get("medical", 0.0), score)
            elif "ip_" in tag_lower or "source_code" in tag_lower or "proprietary" in tag_lower:
                category_breakdown["ip"] = max(category_breakdown.get("ip", 0.0), score)
            elif "confidential" in tag_lower or "financial" in tag_lower or "business" in tag_lower:
                category_breakdown["business_confidential"] = max(category_breakdown["business_confidential"], score)
            elif "privacy" in tag_lower or "credential" in tag_lower or "password" in tag_lower or "employee" in tag_lower:
                category_breakdown["privacy"] = max(category_breakdown["privacy"], score)
            elif "harmful" in tag_lower or "violence" in tag_lower or "malware" in tag_lower or "illegal" in tag_lower:
                category_breakdown["harmful"] = max(category_breakdown.get("harmful", 0.0), score)
            elif "social_engineering" in tag_lower or "impersonat" in tag_lower:
                category_breakdown["social_engineering"] = max(category_breakdown.get("social_engineering", 0.0), score)
            else:
                category_breakdown["security"] = max(category_breakdown["security"], score)

        # 3. Map Specialized Scores
        for tag, score in spec_scores.items():
            tag_lower = tag.lower()
            if tag_lower.startswith("pii_"):
                category_breakdown["privacy"] = max(category_breakdown["privacy"], score)
                category_breakdown["pii"] = max(category_breakdown.get("pii", 0.0), score)
            elif tag_lower.startswith("jailbreak_"):
                category_breakdown["security"] = max(category_breakdown["security"], score)
                category_breakdown["jailbreak"] = max(category_breakdown.get("jailbreak", 0.0), score)
            elif tag_lower.startswith("safety_"):
                if "hate" in tag_lower:
                    category_breakdown["harmful"] = max(category_breakdown.get("harmful", 0.0), score)
                    category_breakdown["hate_speech"] = max(category_breakdown.get("hate_speech", 0.0), score)
                elif "violence" in tag_lower:
                    category_breakdown["harmful"] = max(category_breakdown.get("harmful", 0.0), score)
                    category_breakdown["violence"] = max(category_breakdown.get("violence", 0.0), score)
                elif "illegal" in tag_lower:
                    category_breakdown["harmful"] = max(category_breakdown.get("harmful", 0.0), score)
                    category_breakdown["illegal_activity"] = max(category_breakdown.get("illegal_activity", 0.0), score)
                elif "cyber" in tag_lower or "malware" in tag_lower:
                    category_breakdown["security"] = max(category_breakdown["security"], score)
                    category_breakdown["malware"] = max(category_breakdown.get("malware", 0.0), score)
                elif "social" in tag_lower:
                    category_breakdown["social_engineering"] = max(category_breakdown.get("social_engineering", 0.0), score)
                else:
                    category_breakdown["harmful"] = max(category_breakdown.get("harmful", 0.0), score)

        # 4. Context and Metadata scores
        if context_scores:
            category_breakdown["context"] = max(context_scores.values())
        if metadata_scores:
            category_breakdown["metadata"] = max(metadata_scores.values())

        # Decision thresholding
        is_restricted = overall_confidence >= self.confidence_threshold

        return ClassificationResult(
            classification=Classification.RESTRICTED if is_restricted else Classification.NORMAL,
            confidence=overall_confidence,
            risk_score=overall_confidence,
            categories=category_breakdown,
            reasons=all_reasons,
            matched_rules=rule_matches,
        )
