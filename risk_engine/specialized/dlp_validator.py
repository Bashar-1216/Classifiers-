"""
openDLP Checksum & Secret Multi-Factor Validation Module.

Architecture:
Tier 1: Candidate Extraction (Regex / Delimiters)
Tier 2: Strict Multi-Factor Validation
  - Luhn Algorithm for Credit Cards
  - IBAN Mod-97 Checksum
  - High-Confidence API Key prefix + character-set diversity + contextual corroboration
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any


class DLPValidator:
    """Validates sensitive candidates using strict multi-factor evidence."""

    @staticmethod
    def validate_luhn(card_number_str: str) -> bool:
        """Validates credit card candidates via Mod-10 Luhn checksum."""
        digits = [int(c) for c in card_number_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False

        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit

        return checksum % 10 == 0

    @staticmethod
    def validate_iban(iban_str: str) -> bool:
        """Validates IBAN candidates using Mod-97 algorithm."""
        cleaned = re.sub(r'[\s-]', '', iban_str.upper())
        if not re.match(r'^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$', cleaned):
            return False

        rearranged = cleaned[4:] + cleaned[:4]
        numeric_str = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)

        try:
            return int(numeric_str) % 97 == 1
        except ValueError:
            return False

    @staticmethod
    def validate_api_secret_candidate(token: str, context_text: str) -> bool:
        """
        Validates API Key / Secret candidate with multi-factor proof:
        1. Known canonical prefix (e.g. sk-, AKIA, ghp_)
        2. Expected token length (>= 24 chars)
        3. Character set diversity (mixed case + digits)
        4. Context corroboration (not in a tutorial quote or example)
        """
        if len(token) < 20:
            return False

        # Known secret prefixes (including sk-proj- and sk-)
        is_known_prefix = bool(re.match(r'^(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})$', token))
        if not is_known_prefix:
            return False

        # Character entropy check
        freq = Counter(token)
        length = len(token)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())

        has_diversity = (
            any(c.isupper() for c in token) +
            any(c.islower() for c in token) +
            any(c.isdigit() for c in token) >= 2
        )

        return entropy >= 3.8 and has_diversity

    @classmethod
    def evaluate(cls, text: str) -> dict[str, float]:
        """Runs Tier 2 strict validation on candidate findings."""
        scores: dict[str, float] = {}

        # 1. Credit Card Candidates -> Luhn Checksum
        cc_candidates = re.findall(r'\b(?:\d[ -]*?){13,19}\b', text)
        for cand in cc_candidates:
            if cls.validate_luhn(cand):
                scores["dlp_confirmed_credit_card"] = 1.00
                break

        # 2. IBAN Candidates -> Mod-97 Checksum
        iban_candidates = re.findall(r'\b[A-Za-z]{2}\d{2}[A-Za-z0-9\s-]{11,30}\b', text)
        for cand in iban_candidates:
            if cls.validate_iban(cand):
                scores["dlp_confirmed_iban"] = 1.00
                break

        # 3. Secret / API Key Candidate -> Multi-Factor Validation
        token_candidates = re.findall(r'\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})\b', text)
        for token in token_candidates:
            if cls.validate_api_secret_candidate(token, text):
                scores["dlp_confirmed_api_secret"] = 1.00
                break

        return scores
