from __future__ import annotations

import logging
import re

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class JailbreakDetector:
    """
    Jailbreak Detector for AI Risk Assessment Gateway.
    Detects jailbreak and injection attempts using declarative security knowledge rules and lexicons.
    """

    def __init__(self) -> None:
        logger.info("Initializing JailbreakDetector from SecurityKnowledgeBundle...")
        bundle = KnowledgeLoader.get_bundle()
        self.rules = [
            r for r in bundle.ingress_rules
            if r.category in ("security", "jailbreak_injection", "jailbreak_role_hijack", "jailbreak_prompt_extraction")
            or "override" in r.name or "injection" in r.name or "hijack" in r.name
        ]
        self._compiled: list[tuple[re.Pattern, str, float]] = []
        for r in self.rules:
            cat = r.category if r.category != "security" else "jailbreak_injection"
            for p in r.patterns:
                self._compiled.append((re.compile(p, re.IGNORECASE), cat, 0.90 if r.severity == "high" else 0.95))

        self.adversarial_words = set(bundle.adversarial_lexicon)
        self.benign_exclusions = bundle.benign_exclusions
        self.inquiry_prefixes = bundle.inquiry_prefixes
        self.quoted_inquiry_markers = bundle.quoted_inquiry_markers

    def _evaluate_patterns(self, text: str) -> dict[str, float]:
        """Evaluate declarative regex patterns."""
        # Check exclusions
        for excl in self.benign_exclusions:
            if excl.search(text):
                return {}

        # If user is asking an educational or definitional question about an attack concept
        is_inquiry = self.inquiry_prefixes and text.strip().lower().startswith(self.inquiry_prefixes)
        if is_inquiry and ("?" in text or "'" in text or '"' in text or "«" in text or ":" in text):
            cleaned_text = re.sub(r"['\"«»“].*?['\"«»”]", "", text)
            if not any(pattern.search(cleaned_text) for pattern, _, _ in self._compiled):
                return {}

        scores: dict[str, float] = {}
        for pattern, category, score in self._compiled:
            if pattern.search(text):
                scores[category] = max(scores.get(category, 0.0), score)
        return scores

    def _evaluate_lexical_overlap(self, text: str) -> float:
        """Evaluate lexical threat overlap against centralized adversarial lexicon."""
        if not self.adversarial_words:
            return 0.0
        words = set(re.findall(r"\w+", text.lower()))
        if not words:
            return 0.0
        overlap = words.intersection(self.adversarial_words)
        if overlap:
            ratio = len(overlap) / min(len(words), 10)
            return min(0.95, ratio * 1.2)
        return 0.0

    def evaluate(self, text: str) -> dict[str, float]:
        """
        Evaluate text for jailbreak attempts using declarative security knowledge.
        """
        if not text.strip():
            return {}

        pattern_scores = self._evaluate_patterns(text)
        lexical_score = self._evaluate_lexical_overlap(text)

        results: dict[str, float] = {}
        for cat, score in pattern_scores.items():
            final_score = max(score, lexical_score)
            results[cat] = round(final_score, 4)

        if not results and lexical_score >= 0.70:
            results["jailbreak_injection"] = round(lexical_score, 4)

        return results
