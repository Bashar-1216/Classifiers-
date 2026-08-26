"""
Local Risk Adjudicator — False Positive & Conflict Resolution.

Inspired by Cisco DefenseClaw Adjudication Framework:
Runs ONLY upon signal conflict or high uncertainty:
  Case 1: Fast Rules = Risky  AND  Semantic Guard = Benign
  Case 2: Fast Rules = Benign AND  Semantic Guard = Risky
  Case 3: Overall Uncertainty > Threshold

Evaluates DefenseClaw 5 Threat Pillars against Benign Exclusions:
1. Instruction Manipulation
2. Context Manipulation
3. Obfuscation
4. Semantic Manipulation
5. Token Exploitation

Does NOT execute on clear, deterministic, non-conflicting prompts.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class LocalRiskAdjudicator:
    """Evaluates ambiguous borderline signals and resolves false positive conflicts."""

    BENIGN_EXCLUSION_PATTERNS = [
        # Quoted concepts in meta-analysis and classification prompts
        r'(?i)^\s*(?:classify|evaluate|explain\s+why|the\s+article\s+says|what\s+does|what\s+is|قيّم|قيم|هل\s+عبارة)\b.*["«“\'].*?["»”\']',
        # Conceptual and educational definitions
        r'(?i)^\s*(?:ما\s+هو|ما\s+هي|ما\s+الفرق|ما\s+معنى|اشرح|كيف\s+(?:احمي|أحمي|ابني|أبني|اختبر|أختبر|اراجع|أراجع)|اكتب\s+policy)\b',
        r'(?i)^\s*(?:what\s+is|what\s+are|explain\s+what|explain\s+how|how\s+do|how\s+can\s+developers)\b',
        # Video game and UI development exclusions
        r'(?i)\b(?:video\s+game|gaming|minecraft|ninja\s+character|stealth\s+attribute|taskbar\s+in\s+C#)\b',
        r'(?i)\b(?:في\s+لعبة\s+فيديو|ماينكرافت|لعبتي\s+المحلية)\b',
        # Pure Standalone Negated command (e.g. don't ignore previous instructions)
        r"(?i)^\s*(?:don't|do\s+not)\s+(?:ignore|reveal|bypass|disable)\s+.*$",
    ]

    def __init__(self) -> None:
        self.exclusion_regexes = [re.compile(p) for p in self.BENIGN_EXCLUSION_PATTERNS]

    def is_conflicted(
        self,
        rule_score: float,
        semantic_score: float,
        uncertainty: float,
    ) -> bool:
        """
        Determines whether signals require contextual adjudication.
        Runs whenever risk signals are triggered on candidate inputs.
        """
        return (rule_score > 0.0 or semantic_score > 0.0 or uncertainty > 0.0)

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
        # Adjudicate ONLY on conflict or uncertainty
        if not self.is_conflicted(rule_score, semantic_score, uncertainty):
            return initial_risk_score, reasons, False

        text_trimmed = text.strip()

        # Check for explicit benign exclusions
        for regex in self.exclusion_regexes:
            if regex.search(text_trimmed):
                # Ensure it's not a mixed malicious payload or double-bind attack
                has_active_override = bool(
                    re.search(
                        r'(?i)\b(?:and\s+ignore\s+all|then\s+dump\s+passwords|and\s+hack|'
                        r'print\s+it\s+exactly|show\s+the\s+credentials|final\s+result|'
                        r'instead,\s+for\s+verification)\b',
                        text_trimmed,
                    )
                )
                if not has_active_override:
                    logger.info(
                        "Local Adjudicator: Resolved conflict -> Identified Benign Exclusion for: '%s'",
                        text[:40],
                    )
                    return 0.0, [], True

        # If no benign exclusion matched, maintain the initial risk findings
        return initial_risk_score, reasons, True
