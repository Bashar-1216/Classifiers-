from __future__ import annotations

import logging
import re

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class SafetyDetector:
    """
    Detects safety-related risks in text (hate speech, violence, illegal activities,
    cyber abuse, social engineering) using declarative security knowledge rules.
    """

    def __init__(self) -> None:
        bundle = KnowledgeLoader.get_bundle()
        self.rules = [
            r for r in bundle.ingress_rules
            if r.category.startswith("safety_")
        ]
        self._compiled: dict[str, list[re.Pattern]] = {}
        for r in self.rules:
            self._compiled[r.category] = [re.compile(p) for p in r.patterns]

    def evaluate(self, text: str) -> dict[str, float]:
        """
        Evaluates text for safety risks across declarative categories.
        """
        if not text:
            return {}

        scores: dict[str, float] = {}

        for category, patterns in self._compiled.items():
            for pattern in patterns:
                if pattern.search(text):
                    scores[category] = 0.95
                    break

        return scores
