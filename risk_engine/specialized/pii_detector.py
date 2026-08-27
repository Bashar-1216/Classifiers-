from __future__ import annotations

import logging
import re

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class PIIDetector:
    """
    Personally Identifiable Information (PII) Detector.
    Uses declarative security knowledge bundle (PII patterns & Secret patterns).
    """

    def __init__(self) -> None:
        bundle = KnowledgeLoader.get_bundle()
        self.pii_patterns = bundle.pii_dlp_patterns
        self.secret_patterns = bundle.secret_dlp_patterns
        
        self.context_record_regex: re.Pattern | None = None
        for p in self.pii_patterns:
            if p.get("id") == "DLP-PII-CONTEXT-RECORD":
                compiled = p.get("compiled_patterns", [])
                if compiled:
                    self.context_record_regex = compiled[0]
                break

    def _luhn_check(self, card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm.
        """
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) < 13:
            return False

        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    def _evaluate_layer1_regex(self, text: str) -> dict[str, float]:
        """
        Layer 1: Regex Pattern Matching using declarative security knowledge.
        """
        scores: dict[str, float] = {}

        for entry in self.pii_patterns:
            category = entry.get("category", "pii_general")
            confidence = entry.get("confidence", 0.85)
            validation = entry.get("validation", "none")
            compiled_patterns = entry.get("compiled_patterns", [])

            for pattern in compiled_patterns:
                for match in pattern.finditer(text):
                    match_val = match.group()
                    if validation == "luhn":
                        if self._luhn_check(match_val):
                            scores[category] = max(scores.get(category, 0.0), confidence)
                    else:
                        scores[category] = max(scores.get(category, 0.0), confidence)
                        break

        return scores

    def _evaluate_layer2_context(
        self, text: str, layer1_scores: dict[str, float]
    ) -> dict[str, float]:
        """
        Layer 2: Entity Context Scoring.
        Looks for structured records or dense presence of PII-related terms.
        """
        scores: dict[str, float] = {}
        text_lower = text.lower()

        # Check structured record
        if self.context_record_regex:
            structured_matches = self.context_record_regex.findall(text)
            if len(structured_matches) >= 2:
                scores["pii_structured_record"] = min(
                    1.0, 0.6 + (len(structured_matches) * 0.1)
                )

        # Co-occurrence density check
        entities_present = 0
        for kw in [
            "name",
            "email",
            "phone",
            "address",
            "patient",
            "customer",
            "employee",
        ]:
            if kw in text_lower:
                entities_present += 1

        if entities_present >= 3 and (
            "pii_email" in layer1_scores or "pii_phone" in layer1_scores
        ):
            scores["pii_context_density"] = min(
                1.0, 0.5 + (entities_present * 0.1)
            )

        return scores

    def _evaluate_layer3_credentials(self, text: str) -> dict[str, float]:
        """
        Layer 3: Credential Detection using declarative security knowledge.
        """
        scores: dict[str, float] = {}

        for entry in self.secret_patterns:
            entry_id = entry.get("id", "").lower().replace("-", "_")
            category = f"pii_credential_{entry_id.replace('dlp_secret_', '')}"
            confidence = entry.get("confidence", 0.90)
            compiled_patterns = entry.get("compiled_patterns", [])

            for pattern in compiled_patterns:
                if pattern.search(text):
                    scores[category] = max(scores.get(category, 0.0), confidence)
                    break

        return scores

    def evaluate(self, text: str) -> dict[str, float]:
        """
        Returns category-to-score mappings like:
        {'pii_credit_card': 0.95, 'pii_email': 0.80, 'pii_credential': 0.90, 'pii_structured_record': 0.75}
        Scores are 0.0 to 1.0. Only include categories with score > 0.
        """
        logger.debug("Evaluating text for PII")
        if not text:
            return {}

        final_scores: dict[str, float] = {}

        # Run 3 layers
        l1_scores = self._evaluate_layer1_regex(text)
        final_scores.update(l1_scores)

        l2_scores = self._evaluate_layer2_context(text, l1_scores)
        final_scores.update(l2_scores)

        l3_scores = self._evaluate_layer3_credentials(text)
        final_scores.update(l3_scores)

        # Consolidate generic pii_credential if any layer 3 rule matched
        if any(k.startswith("pii_credential_") for k in final_scores):
            max_cred = max(
                v
                for k, v in final_scores.items()
                if k.startswith("pii_credential_")
            )
            final_scores["pii_credential"] = max_cred

        # Filter valid scores
        return {
            k: min(1.0, max(0.0, v)) for k, v in final_scores.items() if v > 0.0
        }
