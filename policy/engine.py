"""
Declarative Policy Decision Engine — Evaluates Versioned Policies.

Transforms a multi-dimensional ClassificationResult and Request Metadata into a deterministic PolicyDecision.
Evaluates declarative governance rules from the external policy store (policy/policies.json).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from classifier.models import Classification, ClassificationResult
from policy.models import PolicyDecision, Route

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATH = Path(__file__).parent / "policies.json"


class PolicyEngine:
    """
    Declarative Policy Decision Engine.
    Evaluates enterprise governance policies from policy/policies.json dynamically.
    """

    def __init__(self, policy_file: Optional[Path | str] = None) -> None:
        self.policy_file = Path(policy_file) if policy_file else DEFAULT_POLICY_PATH
        self.policies: Dict[str, Any] = {}
        self.rules: List[Dict[str, Any]] = []
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
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Evaluate classification result and metadata against declarative policy rules.

        Args:
            classification_result: Multi-dimensional output from AI Risk Assessment Layer.
            metadata: Optional request metadata (role, department, project sensitivity).

        Returns:
            PolicyDecision with designated Route and audit reasoning.
        """
        try:
            meta = metadata or {}
            risk_score = classification_result.risk_score or classification_result.confidence
            categories = classification_result.categories or {}

            is_role_exempted = False

            # Evaluate each declarative rule in order of priority
            for rule in self.rules:
                action_str = rule.get("action", "SHIELD").upper()
                action_route = Route[action_str]

                # 1. Category Score Condition (with optional metadata field exclusion)
                if "category" in rule:
                    cat_name = rule["category"]
                    min_score = float(rule.get("min_score", 0.50))
                    # Match exact category or any subcategory key containing the prefix
                    matching_scores = [v for k, v in categories.items() if cat_name in k]
                    cat_score = max(matching_scores) if matching_scores else categories.get(cat_name, 0.0)

                    if cat_score >= min_score:
                        # Check if an exclude_values filter is present (e.g. doctor role allowed)
                        if "metadata_field" in rule and "exclude_values" in rule:
                            field = rule["metadata_field"]
                            exclude_vals = [str(v).lower() for v in rule.get("exclude_values", [])]
                            current_val = str(meta.get(field, "")).lower()
                            if current_val in exclude_vals:
                                is_role_exempted = True
                                continue  # Permitted for authorized role!

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
                        continue  # Do not block role-authorized domain requests
                    min_risk = float(rule["min_overall_risk"])
                    if risk_score >= min_risk:
                        return PolicyDecision(
                            route=action_route,
                            reason=(
                                f"RESTRICTED — Triggered Policy [{rule.get('id', 'POL')} - {rule.get('name')}]: "
                                f"overall risk score {risk_score:.2f} >= threshold {min_risk:.2f}"
                            ),
                            classification_result=classification_result,
                        )

            # Check direct Classification enum if no specific rule matched
            if classification_result.classification == Classification.RESTRICTED and not is_role_exempted:
                return PolicyDecision(
                    route=Route.SHIELD,
                    reason=f"RESTRICTED — Classification fallback (confidence={risk_score:.2f})",
                    classification_result=classification_result,
                )

            # Default Route (Clean request)
            return PolicyDecision(
                route=self.default_route,
                reason=f"NORMAL — Request passed all governance policies (risk_score={risk_score:.2f})",
                classification_result=classification_result,
            )

        except Exception as e:
            # Any error during policy evaluation must FAIL CLOSED to SHIELD (SR-3)
            logger.error("Policy evaluation exception: %s", e)
            return PolicyDecision(
                route=Route.SHIELD,
                reason=f"FAIL CLOSED — Policy evaluation error: {e}",
                classification_result=classification_result,
            )
