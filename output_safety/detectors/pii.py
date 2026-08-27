"""
PII Detector & Redactor for Model Outputs.

Scans model responses for sensitive Personally Identifiable Information:
- Social Security Numbers (SSN)
- Credit Card Numbers (Visa, MasterCard, Amex) with Luhn validation
- Phone numbers (International and Middle Eastern formats)
- Email addresses
Provides safe redaction replacing detected entities with standard tokens.
"""

from __future__ import annotations

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class OutputPIIDetector:
    """
    Detects and sanitizes PII in AI model responses using declarative security knowledge.
    """

    def __init__(self) -> None:
        bundle = KnowledgeLoader.get_bundle()
        self.dlp_patterns = bundle.pii_dlp_patterns

    @classmethod
    def _luhn_verify(cls, card_str: str) -> bool:
        """Verify credit card number with Luhn algorithm."""
        digits = [int(c) for c in card_str if c.isdigit()]
        if len(digits) < 13:
            return False
        checksum = 0
        reverse = digits[::-1]
        for i, d in enumerate(reverse):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    def evaluate(self, text: str) -> dict[str, float]:
        """
        Scan text for PII entities using declarative bundle patterns.
        """
        if not text:
            return {}

        scores: dict[str, float] = {}

        for entry in self.dlp_patterns:
            category = entry.get("category", "pii_general")
            confidence = entry.get("confidence", 0.85)
            validation = entry.get("validation", "none")
            compiled_patterns = entry.get("compiled_patterns", [])

            for pattern in compiled_patterns:
                for match in pattern.finditer(text):
                    match_val = match.group()
                    if validation == "luhn" and not self._luhn_verify(match_val):
                        continue
                    scores[category] = max(scores.get(category, 0.0), confidence)
                    break

        return scores

    def redact(self, text: str) -> str:
        """
        Mask detected PII (SSN, Credit Cards, Emails, Phone Numbers) with standardized redaction tokens.
        """
        if not text:
            return text

        redacted = text
        for entry in self.dlp_patterns:
            category = entry.get("category", "pii_general")
            validation = entry.get("validation", "none")
            compiled_patterns = entry.get("compiled_patterns", [])
            token = "[REDACTED-" + category.replace("pii_", "").upper() + "]"

            for pattern in compiled_patterns:
                if validation == "luhn":
                    def replace_card(m: re.Match) -> str:
                        return token if self._luhn_verify(m.group()) else m.group()
                    redacted = pattern.sub(replace_card, redacted)
                else:
                    redacted = pattern.sub(token, redacted)

        return redacted
