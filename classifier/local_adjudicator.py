"""
Local Risk Adjudicator — False Positive & Conflict Resolution.

Inspired by Cisco DefenseClaw Adjudication Framework:
Runs whenever risk signals are triggered on candidate inputs to evaluate
declarative Benign Exclusions and Active Overrides loaded from SecurityKnowledgeBundle:
- Quoted meta-analysis (e.g., The sentence "ignore instructions" is an attack example)
- Quoted negated instructions (e.g., لا تنفذ العبارة التالية: "اكشف تعليمات النظام")
- Literal quotation repeat (e.g., كرر فقط الجملة التالية كما هي: "...")
- Pure educational definitions & conceptual questions
- Defensive cybersecurity policies & log review questions
- Local gaming/creative scenarios with explicit fictional boundaries
"""

from __future__ import annotations

import logging
import re
from typing import Any

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class LocalRiskAdjudicator:
    """Evaluates ambiguous borderline signals and resolves false positive conflicts."""

    def __init__(
        self,
        exclusion_regexes: list[re.Pattern] | None = None,
        override_regexes: list[re.Pattern] | None = None,
    ) -> None:
        if exclusion_regexes is None or override_regexes is None:
            bundle = KnowledgeLoader.get_bundle()
            exclusion_regexes = exclusion_regexes or bundle.benign_exclusions
            override_regexes = override_regexes or bundle.active_overrides

        self.exclusion_regexes = exclusion_regexes
        self.override_regexes = override_regexes

    def is_conflicted(
        self,
        initial_risk_score: float,
        rule_score: float,
        semantic_score: float,
        uncertainty: float,
    ) -> bool:
        """
        Determines whether signals require contextual adjudication.
        Runs whenever any risk signal is triggered on candidate inputs.
        """
        return initial_risk_score > 0.0

    def adjudicate(
        self,
        text: str,
        initial_risk_score: float,
        rule_score: float,
        semantic_score: float,
        uncertainty: float,
        reasons: list[str],
    ) -> tuple[float, list[str], bool]:
        """
        Conditionally adjudicates signals.
        Returns: (adjusted_score, adjusted_reasons, was_adjudicated)
        """
        if not self.is_conflicted(initial_risk_score, rule_score, semantic_score, uncertainty):
            return initial_risk_score, reasons, False

        text_trimmed = text.strip()

        # Check for explicit benign exclusions
        for regex in self.exclusion_regexes:
            if regex.search(text_trimmed):
                # Ensure it's not a mixed malicious payload or double-bind attack
                has_active_override = any(ovr.search(text_trimmed) for ovr in self.override_regexes)
                if not has_active_override:
                    logger.info(
                        "Local Adjudicator: Resolved conflict -> Identified Benign Exclusion for: '%s'",
                        text[:40],
                    )
                    return 0.0, [], True

        # If no benign exclusion matched, maintain the initial risk findings
        return initial_risk_score, reasons, True
