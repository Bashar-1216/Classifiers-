"""
Secrets and Credentials Detector for Model Outputs.

Scans model responses for leaked credentials, private keys, and API tokens:
- Private cryptographic keys (RSA, DSA, EC, OPENSSH, PGP)
- Cloud provider keys (AWS, GCP, Azure)
- SaaS API tokens (GitHub, Stripe, Slack, OpenAI)
- Database credentials and connection strings
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class SecretsDetector:
    """
    Detects exposed secrets and credentials in model outputs using declarative security knowledge.
    """

    def __init__(self) -> None:
        bundle = KnowledgeLoader.get_bundle()
        self.secret_patterns = bundle.secret_dlp_patterns

    def evaluate(self, text: str) -> dict[str, float]:
        """
        Scan text for leaked secrets using declarative bundle patterns.

        Returns:
            Dict mapping secret category to confidence score (1.0 = critical leak).
        """
        if not text:
            return {}

        scores: dict[str, float] = {}

        for entry in self.secret_patterns:
            category = entry.get("category", "secret_generic")
            confidence = entry.get("confidence", 0.95)
            compiled_patterns = entry.get("compiled_patterns", [])

            for pattern in compiled_patterns:
                if pattern.search(text):
                    scores[category] = max(scores.get(category, 0.0), confidence)
                    break

        return scores
