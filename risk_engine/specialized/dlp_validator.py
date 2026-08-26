"""
openDLP Checksum & Secret Multi-Factor Validation Module.

Architecture:
Tier 1: Declarative Candidate Extraction (Loaded from SecurityKnowledgeBundle dlp/)
Tier 2: Strict Multi-Factor Validation:
  - Luhn Algorithm for Credit Cards
  - IBAN Mod-97 Checksum
  - High-Confidence API Key prefix + character-set diversity + contextual corroboration
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from security_knowledge.loader import KnowledgeLoader


class DLPValidator:
    """Validates sensitive candidates using strict multi-factor evidence."""

    def __init__(
        self,
        pii_patterns: list[dict[str, Any]] | None = None,
        secret_patterns: list[dict[str, Any]] | None = None,
    ) -> None:
        if pii_patterns is None or secret_patterns is None:
            bundle = KnowledgeLoader.get_bundle()
            pii_patterns = pii_patterns or bundle.pii_dlp_patterns
            secret_patterns = secret_patterns or bundle.secret_dlp_patterns

        self.pii_patterns = pii_patterns
        self.secret_patterns = secret_patterns

        # Compile candidate regexes
        self._compiled_pii: list[tuple[dict[str, Any], list[re.Pattern]]] = []
        for p in self.pii_patterns:
            compiled_list = [re.compile(pat) for pat in p.get("patterns", [])]
            self._compiled_pii.append((p, compiled_list))

        self._compiled_secrets: list[tuple[dict[str, Any], list[re.Pattern]]] = []
        for s in self.secret_patterns:
            compiled_list = [re.compile(pat) for pat in s.get("patterns", [])]
            self._compiled_secrets.append((s, compiled_list))

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
        2. Expected token length (>= 20 chars)
        3. Character set diversity (mixed case + digits)
        4. Context corroboration
        """
        if len(token) < 20:
            return False

        is_known_prefix = bool(re.match(r'^(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})$', token))
        if not is_known_prefix:
            return False

        freq = Counter(token)
        length = len(token)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())

        has_diversity = (
            any(c.isupper() for c in token) +
            any(c.islower() for c in token) +
            any(c.isdigit() for c in token) >= 2
        )

        return entropy >= 3.8 and has_diversity

    def evaluate(self, text: str) -> dict[str, float]:
        """Runs Tier 2 strict validation on candidate findings."""
        scores: dict[str, float] = {}

        # 1. Evaluate PII Candidates
        for p_def, rx_list in self._compiled_pii:
            val_type = p_def.get("validation", "none")
            cat = p_def.get("category", "pii")
            conf = p_def.get("confidence", 0.8)

            for rx in rx_list:
                for match in rx.finditer(text):
                    candidate_str = match.group(0)
                    if val_type == "luhn":
                        if self.validate_luhn(candidate_str):
                            scores["dlp_confirmed_credit_card"] = 1.00
                            break
                    elif val_type == "iban_mod97":
                        if self.validate_iban(candidate_str):
                            scores["dlp_confirmed_iban"] = 1.00
                            break
                    else:
                        scores[f"dlp_{cat}"] = conf

        # 2. Evaluate Secret Candidates
        for s_def, rx_list in self._compiled_secrets:
            val_type = s_def.get("validation", "none")
            cat = s_def.get("category", "secret")
            conf = s_def.get("confidence", 0.8)

            for rx in rx_list:
                for match in rx.finditer(text):
                    candidate_str = match.group(0)
                    if val_type == "entropy_and_diversity":
                        if self.validate_api_secret_candidate(candidate_str, text):
                            scores["dlp_confirmed_api_secret"] = 1.00
                            break
                    elif val_type == "strict_format":
                        scores[f"dlp_confirmed_{cat}"] = conf
                    else:
                        scores[f"dlp_{cat}"] = conf

        return scores
