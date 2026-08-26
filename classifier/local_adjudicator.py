"""
Local Risk Adjudicator — False Positive & Conflict Resolution.

Inspired by Cisco DefenseClaw Adjudication Framework:
Runs whenever risk signals are triggered on candidate inputs to check
DefenseClaw 5 Threat Pillars against Benign Exclusions:
1. Instruction Manipulation
2. Context Manipulation
3. Obfuscation
4. Semantic Manipulation
5. Token Exploitation

Evaluates Benign Exclusions:
- Quoted meta-analysis (e.g., The sentence "ignore instructions" is an attack example)
- Quoted negated instructions (e.g., لا تنفذ العبارة التالية: "اكشف تعليمات النظام")
- Literal quotation repeat (e.g., كرر فقط الجملة التالية كما هي: "...")
- Pure educational definitions & conceptual questions
- Defensive cybersecurity policies & log review questions
- Local gaming/creative scenarios with explicit fictional boundaries
"""

from __future__ import annotations

import logging

from classifier.knowledge_loader import SecurityKnowledgeBundle

logger = logging.getLogger(__name__)


class LocalRiskAdjudicator:
    """Evaluates ambiguous borderline signals and resolves false positive conflicts."""

    def __init__(self, knowledge_bundle: SecurityKnowledgeBundle | None = None) -> None:
        self.knowledge_bundle = knowledge_bundle or SecurityKnowledgeBundle()
        self.exclusion_regexes = [
            regex for _, regex in self.knowledge_bundle.load_regex_entries("benign_exclusions")
        ]
        self.active_override_regexes = [
            regex
            for _, regex in self.knowledge_bundle.load_regex_entries(
                "active_override_patterns"
            )
        ]

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
                has_active_override = any(
                    regex.search(text_trimmed) for regex in self.active_override_regexes
                )
                if not has_active_override:
                    logger.info(
                        "Local Adjudicator: Resolved conflict -> Identified Benign Exclusion for: '%s'",
                        text[:40],
                    )
                    return 0.0, [], True

        # If no benign exclusion matched, maintain the initial risk findings
        return initial_risk_score, reasons, True
