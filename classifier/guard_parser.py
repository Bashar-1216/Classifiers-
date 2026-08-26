"""
Deterministic Parser & Taxonomy Mapper for Neural Guard Outputs.
Ensures zero unhandled formatting errors, regex resilience, and safe defaults.
"""

from __future__ import annotations

import re
from typing import List, Tuple
from classifier.guard_models import GuardVerdict

# Canonical mapping for Llama Guard 3 hazard codes
DEFAULT_CATEGORY_MAPPING = {
    "S1": "violent_crimes",
    "S2": "non_violent_crimes",
    "S3": "sex_related_crimes",
    "S4": "child_sexual_exploitation",
    "S5": "defamation",
    "S6": "specialized_advice",
    "S7": "privacy_pii",
    "S8": "intellectual_property",
    "S9": "indiscriminate_weapons",
    "S10": "hate_speech",
    "S11": "suicide_self_harm",
    "S12": "sexual_content",
    "S13": "elections_misinformation",
    "S14": "code_interpreter_abuse",
}

# Regex to safely find category codes like S1, S2, S14
CATEGORY_CODE_PATTERN = re.compile(r"\bS(?:[1-9]|1[0-4])\b", re.IGNORECASE)


class GuardOutputParser:
    """
    Parses and sanitizes raw model output strings into typed verdicts and categories.
    """

    def __init__(self, taxonomy_mapping: dict[str, str] | None = None) -> None:
        self.taxonomy_mapping = taxonomy_mapping or DEFAULT_CATEGORY_MAPPING

    def parse(self, raw_text: str) -> Tuple[GuardVerdict, List[str], List[str]]:
        """
        Parse raw response text into (GuardVerdict, raw_categories, canonical_categories).
        
        Guarantees:
        - If 'unsafe' is present in the output, returns GuardVerdict.UNSAFE.
        - If 'safe' is present (and not unsafe), returns GuardVerdict.SAFE.
        - If output is empty or unrecognized, returns GuardVerdict.ERROR.
        """
        if not raw_text or not raw_text.strip():
            return GuardVerdict.ERROR, [], []

        cleaned = raw_text.strip()
        cleaned_lower = cleaned.lower()

        # Check for UNSAFE
        if "unsafe" in cleaned_lower:
            verdict = GuardVerdict.UNSAFE
            # Extract category codes
            raw_codes = [c.upper() for c in CATEGORY_CODE_PATTERN.findall(cleaned)]
            # Deduplicate preserving order
            raw_categories = list(dict.fromkeys(raw_codes))
            canonical_categories = [
                self.taxonomy_mapping.get(code, f"unknown_category_{code.lower()}")
                for code in raw_categories
            ]
            return verdict, raw_categories, canonical_categories

        # Check for SAFE
        if "safe" in cleaned_lower:
            return GuardVerdict.SAFE, [], []

        # Malformed / Unrecognized output
        return GuardVerdict.ERROR, [], []
