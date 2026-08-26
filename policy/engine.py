"""
Declarative Policy Decision Engine — Evaluates Versioned Policies.

Transforms a multi-dimensional ClassificationResult, Neural Guard Evidence, and Metadata
into a deterministic PolicyDecision with Route.NORMAL or Route.SHIELD.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from classifier.models import Classification, ClassificationResult
from classifier.guard_models import GuardEvidence, GuardVerdict
from policy.models import PolicyDecision, Route

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATH = Path(__file__).parent / "policies.json"


class PolicyEngine:
    """
    Declarative Policy Decision Engine.
    Evaluates enterprise governance policies from policy/policies.json dynamically.
    """

    def __init__(self, policy_file: Path | str | None = None) -> None:
        self.policy_file = Path(policy_file) if policy_file else DEFAULT_POLICY_PATH
        self.policies: dict[str, Any] = {}
        self.rules: list[dict[str, Any]] = []
        self.default_route = Route.NORMAL
        self.default_risk_threshold = 0.50

        self.load_policies()

    def load_policies(self) -> None:
        """Load declarative policy rules from JSON policy store."""
        if self.policy_file.exists():
            try:
                with open(self.policy_file, "r", encoding="utf-8") as f:
                    self.policies = json.load(f)
                    self.rules = self.policies.get("rules", [])
                    default_route_str = self.policies.get("default_route", "NORMAL").upper()
                    self.default_route = Route[default_route_str]
                    self.default_risk_threshold = float(self.policies.get("default_risk_threshold", 0.50))
                logger.info(
                    "PolicyEngine loaded %d declarative governance rules from %s",
                    len(self.rules),
                    self.policy_file,
                )
                return
            except Exception as exc:
                logger.warning("Failed to load policy file %s: %s (using defaults)", self.policy_file, exc)

        # Fallback default rules
        self.rules = [
            {"id": "FALLBACK-001", "name": "Default Overall Risk", "min_overall_risk": 0.50, "action": "SHIELD"}
        ]

    def evaluate(
        self,
        classification_result: ClassificationResult,
        metadata: dict[str, Any] | None = None,
        guard_evidence: Optional[GuardEvidence] = None,
    ) -> PolicyDecision:
        """
        Evaluate classification result and metadata against declarative policy rules.
        """
        try:
            meta = metadata or {}
            risk_score = classification_result.risk_score or classification_result.confidence
            categories = classification_result.categories or {}

            # Check if guard evidence was attached in reasons or passed directly
            reasons_str = " ".join(classification_result.reasons)
            has_guard_unsafe = (guard_evidence and guard_evidence.verdict == GuardVerdict.UNSAFE) or ("neural_guard_unsafe" in reasons_str)
            has_guard_unavailable = (guard_evidence and guard_evidence.verdict == GuardVerdict.UNAVAILABLE) or ("neural_guard_unavailable" in reasons_str)

            is_role_exempted = False

            # Evaluate each declarative rule in order of priority
            for rule in self.rules:
                action_str = rule.get("action", "SHIELD").upper()
                action_route = Route[action_str]

                # 0. Neural Guard Direct Verdict Condition
                if "guard_verdict" in rule:
                    required_verdict = rule["guard_verdict"].upper()
                    if required_verdict == "UNSAFE" and has_guard_unsafe:
                        return PolicyDecision(
                            route=action_route,
                            reason=f"RESTRICTED — [{rule.get('id')}]: Neural Guard identified active semantic hazard.",
                            classification_result=classification_result,
                        )
                    if required_verdict == "UNAVAILABLE" and has_guard_unavailable:
                        return PolicyDecision(
                            route=action_route,
                            reason=f"RESTRICTED — [{rule.get('id')}]: Fail-Closed triggered due to Guard service unavailability.",
                            classification_result=classification_result,
                        )

                # 1. Category Score Condition
                if "category" in rule:
                    cat_name = rule["category"]
                    min_score = float(rule.get("min_score", 0.50))
                    matching_scores = [v for k, v in categories.items() if cat_name in k]
                    cat_score = max(matching_scores) if matching_scores else categories.get(cat_name, 0.0)

                    if cat_score >= min_score:
                        if "metadata_field" in rule and "exclude_values" in rule:
                            field = rule["metadata_field"]
                            exclude_vals = [str(v).lower() for v in rule.get("exclude_values", [])]
                            current_val = str(meta.get(field, "")).lower()
                            if current_val in exclude_vals:
                                is_role_exempted = True
                                continue

                        return PolicyDecision(
                            route=action_route,
                            reason=(
                                f"RESTRICTED — Triggered Policy [{rule.get('id', 'POL')} - {rule.get('name')}]: "
                                f"category '{cat_name}' score {cat_score:.2f} >= threshold {min_score:.2f}"
                            ),
                            classification_result=classification_result,
                        )

                # 2. Metadata Field Matching Condition
                if "metadata_field" in rule:
                    field = rule["metadata_field"]
                    match_values = [str(v).lower() for v in rule.get("match_values", [])]
                    current_val = str(meta.get(field, "")).lower()

                    if current_val in match_values:
                        min_risk = rule.get("min_overall_risk")
                        if min_risk is None or risk_score >= float(min_risk):
                            return PolicyDecision(
                                route=action_route,
                                reason=(
                                    f"RESTRICTED — Triggered Policy [{rule.get('id', 'POL')} - {rule.get('name')}]: "
                                    f"metadata '{field}'='{current_val}' matched restricted policy"
                                ),
                                classification_result=classification_result,
                            )

                # 3. Overall Risk Score Condition
                if "min_overall_risk" in rule and "metadata_field" not in rule and "category" not in rule:
                    if is_role_exempted:
                        continue
                    min_risk = float(rule["min_overall_risk"])
                    if risk_score >= min_risk:
                        return PolicyDecision(
                            route=action_route,
                            reason=(
                                f"RESTRICTED — Triggered Policy [{rule.get('id', 'POL')} - {rule.get('name')}]: "
                                f"overall risk {risk_score:.2f} >= threshold {min_risk:.2f}"
                            ),
                            classification_result=classification_result,
                        )

            # Default fallback when no restricted policy matches
            if classification_result.classification == Classification.RESTRICTED:
                return PolicyDecision(
                    route=Route.SHIELD,
                    reason="RESTRICTED — Fallback isolation for restricted classification.",
                    classification_result=classification_result,
                )

            return PolicyDecision(
                route=self.default_route,
                reason="NORMAL — Evaluated all declarative governance policies with zero violations.",
                classification_result=classification_result,
            )

        except Exception as exc:
            logger.error("Error evaluating policies (failing closed to SHIELD): %s", exc)
            return PolicyDecision(
                route=Route.SHIELD,
                reason=f"RESTRICTED — PolicyEngine evaluation error: {exc} (Fail-Closed to Air-Gapped Shield)",
                classification_result=classification_result,
            )
