"""
Output Policy Detector.

Evaluates model responses against output safety policies:
- System prompt leak / internal directive exposure
- Dangerous exploit payload generation
- Raw command execution scripts
"""

from __future__ import annotations

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class OutputPolicyDetector:
    """
    Evaluates model outputs against security policy constraints using declarative security knowledge.
    """

    def __init__(self) -> None:
        bundle = KnowledgeLoader.get_bundle()
        self.rules = [
            r for r in bundle.ingress_rules
            if r.category.startswith("policy_") or r.name.startswith("output_")
        ]
        self._compiled: dict[str, list[re.Pattern]] = {}
        for r in self.rules:
            self._compiled[r.category] = [re.compile(p) for p in r.patterns]

    def evaluate(self, text: str) -> dict[str, float]:
        """
        Scan response text for policy violations using declarative security knowledge.
        """
        if not text:
            return {}

        scores: dict[str, float] = {}

        for category, patterns in self._compiled.items():
            for pattern in patterns:
                if pattern.search(text):
                    scores[category] = 1.0 if "exploit" in category else 0.90
                    break

        return scores
