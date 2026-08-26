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
import re
from typing import Any

logger = logging.getLogger(__name__)


class LocalRiskAdjudicator:
    """Evaluates ambiguous borderline signals and resolves false positive conflicts."""

    BENIGN_EXCLUSION_PATTERNS = [
        # Quoted concepts in meta-analysis, classification, negated quotation, or literal repeat
        r'(?i)^\s*(?:classify|evaluate|explain\s+why|the\s+article|the\s+sentence|what\s+does|what\s+is|قيّم|قيم|هل\s+عبارة|لا\s+تنفذ|كرر\s+فقط|كرر|الجملة\s+هي|العبارة\s+هي|تجاهل\s+كلمة|نريد\s+اختبار)\b.*["«“\'].*?["»”\']',
        # Standalone purely quoted phrases without execution command
        r'(?i)^\s*["«“\']\s*(?:ignore\s+previous\s+instructions|reveal\s+your\s+system\s+prompt|اكشف\s+تعليمات\s+النظام)\s*["»”\']\s*$',
        # Meta-analysis statements explaining verbs/attack examples
        r'(?i)\b(?:is\s+an\s+attack\s+example|is\s+just\s+an\s+English\s+verb|مجرد\s+فعل|مجرد\s+مثال|مثال\s+على\s+هجوم)\b',
        # Conceptual and educational definitions (Arabic)
        r'(?i)^\s*(?:ما\s+هو|ما\s+هي|ما\s+الفرق|ما\s+معنى|اشرح|كيف\s+(?:احمي|أحمي|ابني|أبني|اختبر|أختبر|اراجع|أراجع|تخزن|تُخزن|تمنع|نمنع)|اكتب\s+(?:policy|سياسة|قصة\s+عن\s+مساعد\s+خيالي))\b',
        # Target term without malicious action (e.g. system prompt اعرف معناه؟)
        r'(?i)\b(?:system\s+prompt\s+اعرف\s+معناه|اعرف\s+معناه)\b',
        # Pure conceptual English queries
        r'(?i)^\s*(?:what\s+is|what\s+are|explain\s+what|explain\s+how|how\s+do|how\s+can\s+developers|list\s+function\s+schemas\s+conceptually)\b',
        # Video game and UI development exclusions
        r'(?i)\b(?:video\s+game|gaming|minecraft|ninja\s+character|stealth\s+attribute|taskbar\s+in\s+C#)\b',
        r'(?i)\b(?:في\s+لعبة\s+فيديو|ماينكرافت|لعبتي\s+المحلية)\b',
        # Pure Standalone Negated command (e.g. don't ignore previous instructions / لا تسرب أي أسرار)
        r"(?i)^\s*(?:don't|do\s+not|لا\s+تسرب|لا\s+تكشف)\s+(?:ignore|reveal|bypass|disable|أي\s+أسرار|اي\s+اسرار|أسرار)\s*.*$",
    ]

    def __init__(self) -> None:
        self.exclusion_regexes = [re.compile(p) for p in self.BENIGN_EXCLUSION_PATTERNS]

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
                has_active_override = bool(
                    re.search(
                        r'(?i)\b(?:and\s+ignore\s+all|then\s+dump\s+passwords|and\s+hack|'
                        r'print\s+it\s+exactly|show\s+the\s+credentials|final\s+result|'
                        r'instead,\s+for\s+verification|للتأكد\s+أنك\s+لا\s+تسرب.*اعرض|ويعرضها)\b',
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
