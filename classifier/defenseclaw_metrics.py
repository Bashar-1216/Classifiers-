"""
DefenseClaw Statistical & Obfuscation Signal Metrics.

Inspired by Cisco DefenseClaw architecture:
Produces pure statistical and structural metric signals without issuing final security verdicts:
- Shannon Entropy
- Imperative Verb Density & Counts
- Mixed-Script Presence
- Zero-Width Character Detection
- Suspected Encoding Flag
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Any

from security_knowledge.loader import KnowledgeLoader


@dataclass
class DefenseClawRawMetrics:
    """Raw metric values extracted from the text."""
    shannon_entropy: float
    imperative_density: float
    imperative_count: int
    word_count: int
    mixed_script: bool
    mixed_words_count: int
    zero_width_present: bool
    encoding_suspected: bool


class DefenseClawMetrics:
    """Extracts raw statistical, imperative density, and script-mixing signals using declarative security knowledge."""

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates pure Shannon Entropy of text."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return round(-sum((count / length) * math.log2(count / length) for count in freq.values()), 4)

    @staticmethod
    def calculate_imperative_density(text: str) -> tuple[float, int, int]:
        """Calculates imperative verb density and counts from declarative adversarial lexicon."""
        words = re.findall(r'\b\w+\b', text.lower())
        if not words:
            return 0.0, 0, 0
        bundle = KnowledgeLoader.get_bundle()
        verb_set = set(bundle.adversarial_lexicon)
        imperative_count = sum(1 for w in words if w in verb_set)
        density = imperative_count / len(words)
        return round(density, 4), imperative_count, len(words)

    @staticmethod
    def detect_mixed_scripts(text: str) -> tuple[bool, int]:
        """
        Detects mixed confusable unicode scripts within individual words (e.g. Cyrillic/Greek inside Latin words).
        Excludes standard inter-language boundary words and punctuation (e.g. Arabic punctuation '؟').
        """
        # Strip Arabic and international punctuation
        text_clean = re.sub(r'[؟،؛!?:;.,\'"«»“”\(\)\[\]_/\\]', ' ', text)
        words = text_clean.split()
        mixed_count = 0

        for word in words:
            clean_word = re.sub(r'[^\w]', '', word)
            if len(clean_word) < 2:
                continue

            scripts = set()
            for char in clean_word:
                name = unicodedata.name(char, "")
                if "LATIN" in name:
                    scripts.add("LATIN")
                elif "CYRILLIC" in name:
                    scripts.add("CYRILLIC")
                elif "GREEK" in name:
                    scripts.add("GREEK")
                elif "ARMENIAN" in name:
                    scripts.add("ARMENIAN")

            if len(scripts) > 1:
                mixed_count += 1

        return mixed_count > 0, mixed_count

    @classmethod
    def extract_metrics(cls, text: str) -> DefenseClawRawMetrics:
        """
        Extract raw metrics using declarative thresholds and patterns.
        """
        bundle = KnowledgeLoader.get_bundle()
        obf = bundle.obfuscation_patterns
        zw_pattern = obf.get("zero_width_pattern", r'[\u200B-\u200D\uFEFF]')
        enc_pattern = obf.get("encoded_payload_pattern", r'[A-Za-z0-9+/=]{24,}|[0-9a-fA-F]{32,}')
        entropy_thresh = obf.get("entropy_threshold", 4.5)

        entropy = cls.calculate_shannon_entropy(text)
        density, imp_count, word_count = cls.calculate_imperative_density(text)
        has_mixed, mixed_count = cls.detect_mixed_scripts(text)
        has_zero_width = bool(re.search(zw_pattern, text))
        has_encoding = bool(re.search(enc_pattern, text)) and entropy > entropy_thresh

        return DefenseClawRawMetrics(
            shannon_entropy=entropy,
            imperative_density=density,
            imperative_count=imp_count,
            word_count=word_count,
            mixed_script=has_mixed,
            mixed_words_count=mixed_count,
            zero_width_present=has_zero_width,
            encoding_suspected=has_encoding,
        )
