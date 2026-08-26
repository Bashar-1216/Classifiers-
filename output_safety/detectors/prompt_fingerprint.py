"""
System Prompt Fuzzy Fingerprint & Leak Detector.

Protects the organization's proprietary system prompts and internal directives
from being echoed or leaked in model outputs using character n-gram shingles,
rolling hashes, and normalized substring containment.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Set

logger = logging.getLogger(__name__)


class PromptFingerprintDetector:
    """
    Detects proprietary system prompt disclosures in model outputs.
    Operates on fuzzy rolling n-gram shingles to catch paraphrased or verbatim leaks.
    """

    DEFAULT_LEAK_THRESHOLD = 0.55

    # Structural system prompt leak indicators
    GENERIC_LEAK_SIGNATURES = [
        re.compile(r'(?i)(?:here\s+is|this\s+is|my)\s+(?:the\s+)?(?:initial\s+|system\s+|original\s+)?(?:prompt|instructions|developer\s+guidelines):?\s*\n'),
        re.compile(r'(?i)<(?:system|instructions|anthropic_thinking_protocol|tool_calling)>\s*you\s+are'),
        re.compile(r'(?i)you\s+are\s+(?:an?\s+)?(?:AI|expert|assistant|agent)\b.*(?:your\s+(?:core\s+)?(?:goal|role|task|instructions)\s+is)'),
        re.compile(r'(?i)(?:إليك|هذه\s+هي)\s+(?:تعليمات|أوامر|توجيهات)\s+(?:النظام|المطور|الأولية)\s*:'),
    ]

    def __init__(
        self,
        protected_prompts: list[str] | None = None,
        leak_threshold: float = DEFAULT_LEAK_THRESHOLD,
        ngram_size: int = 5,
    ) -> None:
        """
        Initialize the prompt fingerprint detector.

        Args:
            protected_prompts: List of protected system prompt texts to shield from leakage.
            leak_threshold: Overlap ratio (0.0 to 1.0) above which an output is considered a leak.
            ngram_size: Shingle size (in words or character blocks) for fingerprinting.
        """
        self.leak_threshold = leak_threshold
        self.ngram_size = ngram_size
        self.protected_prompts = protected_prompts or []

        # Load from environment if available
        env_prompt = os.getenv("PROTECTED_SYSTEM_PROMPT")
        if env_prompt and env_prompt not in self.protected_prompts:
            self.protected_prompts.append(env_prompt)

        # Precompute shingles for protected prompts
        self.protected_shingles: list[Set[str]] = [
            self._compute_shingles(p) for p in self.protected_prompts if p.strip()
        ]

    def add_protected_prompt(self, prompt_text: str) -> None:
        """Register a new system prompt to protect."""
        if prompt_text and prompt_text not in self.protected_prompts:
            self.protected_prompts.append(prompt_text)
            self.protected_shingles.append(self._compute_shingles(prompt_text))

    def _normalize(self, text: str) -> str:
        """Normalize text for invariant fingerprint matching."""
        text = text.lower()
        text = re.sub(r'[^\w\s]', ' ', text)
        return re.sub(r'\s+', ' ', text).strip()

    def _compute_shingles(self, text: str) -> Set[str]:
        """Compute rolling word n-gram shingles."""
        norm_text = self._normalize(text)
        words = norm_text.split()
        if len(words) < self.ngram_size:
            return {norm_text} if norm_text else set()

        shingles = set()
        for i in range(len(words) - self.ngram_size + 1):
            shingle = " ".join(words[i : i + self.ngram_size])
            shingles.add(shingle)
        return shingles

    def evaluate(self, response_text: str) -> dict[str, Any]:
        """
        Evaluate output text for system prompt disclosures.

        Returns:
            Dict containing:
            - is_leak (bool): True if system prompt leakage is detected.
            - leak_score (float): Overlap or confidence score.
            - reasons (list[str]): Explanation reasons.
        """
        if not response_text or not response_text.strip():
            return {"is_leak": False, "leak_score": 0.0, "reasons": []}

        reasons: list[str] = []
        max_overlap = 0.0

        # 1. Fuzzy Shingle Containment against Registered Protected Prompts
        if self.protected_shingles:
            resp_shingles = self._compute_shingles(response_text)
            if resp_shingles:
                for idx, prot_set in enumerate(self.protected_shingles):
                    if not prot_set:
                        continue
                    # Containment: how much of the protected prompt is present in the response
                    intersection = prot_set.intersection(resp_shingles)
                    containment = len(intersection) / len(prot_set)

                    if containment > max_overlap:
                        max_overlap = containment

                    if containment >= self.leak_threshold:
                        reasons.append(
                            f"Protected system prompt fingerprint leak detected (containment={containment:.2f} >= {self.leak_threshold:.2f})"
                        )

        # 2. Structural Boilerplate Signatures Check
        for sig in self.GENERIC_LEAK_SIGNATURES:
            if sig.search(response_text):
                reasons.append(f"Structural system prompt header leakage pattern matched: '{sig.pattern[:35]}...'")
                max_overlap = max(max_overlap, 0.85)

        is_leak = max_overlap >= self.leak_threshold or len(reasons) > 0
        return {
            "is_leak": is_leak,
            "leak_score": round(max_overlap, 4),
            "reasons": reasons,
        }
