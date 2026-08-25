"""
PII Detector & Redactor for Model Outputs.

Scans model responses for sensitive Personally Identifiable Information:
- Social Security Numbers (SSN)
- Credit Card Numbers (Visa, MasterCard, Amex) with Luhn validation
- Phone numbers
- Email addresses
Provides safe redaction replacing detected entities with standard tokens.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class OutputPIIDetector:
    """
    Detects and sanitizes PII in AI model responses.
    """

    SSN_PATTERN = re.compile(r"\b(?!(?:000|666|9))\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
    
    # Credit Cards
    VISA_PATTERN = re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b")
    MASTERCARD_PATTERN = re.compile(
        r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b"
    )
    AMEX_PATTERN = re.compile(r"\b3[47][0-9]{13}\b")
    FORMATTED_CARD_PATTERN = re.compile(r"\b(?:\d{4}[-\s]){3}\d{4}\b")

    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    PHONE_PATTERN = re.compile(
        r"(?:\+|00)(?:966|971|20|962|964|961|1|44)[ \-\.]?[0-9]{7,12}\b|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"
    )

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

    def evaluate(self, text: str) -> Dict[str, float]:
        """
        Scan text for PII entities.

        Returns:
            Dict mapping PII category to confidence score.
        """
        if not text:
            return {}

        scores: Dict[str, float] = {}

        if self.SSN_PATTERN.search(text):
            scores["pii_ssn"] = 0.95

        # Check credit cards with Luhn validation
        for pattern in (self.VISA_PATTERN, self.MASTERCARD_PATTERN, self.AMEX_PATTERN, self.FORMATTED_CARD_PATTERN):
            for match in pattern.finditer(text):
                if self._luhn_verify(match.group()):
                    scores["pii_credit_card"] = 0.95
                    break

        if self.EMAIL_PATTERN.search(text):
            scores["pii_email"] = 0.80

        if self.PHONE_PATTERN.search(text):
            scores["pii_phone"] = 0.75

        return scores

    def redact(self, text: str) -> str:
        """
        Mask detected PII with standardized redaction tokens.
        """
        if not text:
            return text

        # Redact SSN
        redacted = self.SSN_PATTERN.sub("[REDACTED-SSN]", text)

        # Redact Credit Cards (validated)
        for pattern in (self.FORMATTED_CARD_PATTERN, self.VISA_PATTERN, self.MASTERCARD_PATTERN, self.AMEX_PATTERN):
            def replace_card(m: re.Match) -> str:
                return "[REDACTED-CARD]" if self._luhn_verify(m.group()) else m.group()
            redacted = pattern.sub(replace_card, redacted)

        return redacted
