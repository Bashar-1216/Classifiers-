"""
Structure Signal Engine — Structural & Sequence-based Security Analysis.

Inspired by vLLM Semantic Router architecture (Apache 2.0):
Measures prompt shape, token density, and semantic sequence ordering:
1. Sequence Ordering (e.g. ignore -> instructions -> reveal -> prompt)
2. Keyword Density (Ratio of override/extraction tokens to total word count)
3. Structural Delimiter Containers (ChatML, System Reminders, XML injections)
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Known adversarial sequence flows
ADVERSARIAL_SEQUENCES: list[list[str]] = [
    ["ignore", "instructions", "show"],
    ["ignore", "instructions", "reveal"],
    ["ignore", "instructions", "print"],
    ["ignore", "rules", "system", "prompt"],
    ["forget", "rules", "developer"],
    ["تجاهل", "التعليمات", "اطبع"],
    ["تجاهل", "التعليمات", "اعرض"],
    ["تجاهل", "الاوامر", "الموجه"],
    ["تجاهل", "القيود", "النظام"],
    ["لا", "تكشف", "اول", "سطر"],
    ["بدون", "ذكر", "اول", "كلمة"],
]

OVERRIDE_VOCAB = {
    "ignore", "disregard", "forget", "override", "bypass", "drop", "disable", "deactivate",
    "unrestricted", "jailbreak", "dan",
    "تجاهل", "الغ", "اسقط", "تجاوز", "عطل"
}


class StructureSignalEngine:
    """Evaluates the structural and sequential shape of the prompt."""

    def __init__(self) -> None:
        self.sequences = ADVERSARIAL_SEQUENCES
        self.override_vocab = OVERRIDE_VOCAB

    def evaluate_sequence(self, text: str) -> float:
        """
        Check if tokens appear in an adversarial sequence order within the prompt.
        Returns a risk score between 0.0 and 1.0.
        """
        text_lower = text.lower()
        words = re.findall(r'\b\w+\b', text_lower)
        if not words:
            return 0.0

        for seq in self.sequences:
            seq_idx = 0
            for word in words:
                if word == seq[seq_idx] or word.startswith(seq[seq_idx]):
                    seq_idx += 1
                    if seq_idx == len(seq):
                        return 0.95  # Full adversarial sequence detected

        return 0.0

    INQUIRY_PREFIXES = (
        "explain", "what is", "how do", "how to", "classify", "the article says", "summarize",
        "write policy", "write a policy", "don't ignore", "do not ignore",
        "اكتب policy", "اشرح", "ما هو", "ما هي", "ما الفرق", "ما معنى", "ما افضل", "ما أفضل",
        "كيف احمي", "كيف أحمي", "كيف اختبر", "كيف أختبر", "كيف ابني", "كيف أبني", "كيف اراجع", "كيف أراجع",
        "اعطني مثالا", "اعطني مثالًا", "اكتب system prompt", "هل عبارة", "قيم ان", "قيّم إن"
    )

    def _is_inquiry_or_educational(self, text: str) -> bool:
        t = text.strip().lower()
        if t.startswith(self.INQUIRY_PREFIXES):
            return True
        if '"' in t or "'" in t or '«' in t or '“' in t:
            if any(p in t for p in ("classify", "article says", "summarize", "explain why", "هل عبارة", "قيم ان", "قيّم إن")):
                return True
        return False

    def evaluate_density(self, text: str) -> float:
        """
        Calculates the density of override/extraction keywords relative to length.
        High density (> 25% hostile keywords) is a strong signal of injection.
        """
        if self._is_inquiry_or_educational(text):
            return 0.0

        words = re.findall(r'\b\w+\b', text.lower())
        if not words or len(words) < 3:
            return 0.0

        override_count = sum(1 for w in words if w in self.override_vocab)
        density = override_count / len(words)

        if density >= 0.35 and override_count >= 2:
            return 0.90
        elif density >= 0.20 and override_count >= 2:
            return 0.70
        elif override_count >= 3:
            return 0.65

        return 0.0

    def evaluate_structure(self, text: str) -> dict[str, float]:
        """
        Run all structural and sequence signals and compile risk evidence.
        """
        scores: dict[str, float] = {}

        seq_score = self.evaluate_sequence(text)
        if seq_score > 0.0:
            scores["structure_adversarial_sequence"] = seq_score

        density_score = self.evaluate_density(text)
        if density_score > 0.0:
            scores["structure_keyword_density"] = density_score

        return scores
