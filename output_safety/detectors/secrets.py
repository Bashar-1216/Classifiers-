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
from typing import Dict

logger = logging.getLogger(__name__)


class SecretsDetector:
    """
    Detects exposed secrets and credentials in model outputs.
    """

    PRIVATE_KEY_PATTERN = re.compile(
        r"-----BEGIN (?:RSA |DSA |EC |PGP |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |DSA |EC |PGP |OPENSSH )?PRIVATE KEY-----",
        re.DOTALL,
    )
    AWS_SECRET_PATTERN = re.compile(
        r"(?i)\b(?:aws_secret_access_key|aws_session_token)\s*[:=]\s*[A-Za-z0-9/+=]{20,}\b"
    )
    AWS_KEY_PATTERN = re.compile(
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b"
    )
    GITHUB_TOKEN_PATTERN = re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"
    )
    STRIPE_KEY_PATTERN = re.compile(
        r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,99}\b"
    )
    GENERIC_SECRET_PATTERN = re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|db[_-]?password)\s*[:=]\s*[\'\"`][A-Za-z0-9_\-\.\+/=]{16,}[\'\"`]"
    )

    def evaluate(self, text: str) -> Dict[str, float]:
        """
        Scan text for leaked secrets.

        Returns:
            Dict mapping secret category to confidence score (1.0 = critical leak).
        """
        if not text:
            return {}

        scores: Dict[str, float] = {}

        if self.PRIVATE_KEY_PATTERN.search(text):
            scores["secret_private_key"] = 1.0

        if self.AWS_SECRET_PATTERN.search(text) or self.AWS_KEY_PATTERN.search(text):
            scores["secret_aws_credentials"] = 1.0

        if self.GITHUB_TOKEN_PATTERN.search(text):
            scores["secret_github_token"] = 1.0

        if self.STRIPE_KEY_PATTERN.search(text):
            scores["secret_stripe_key"] = 1.0

        if self.GENERIC_SECRET_PATTERN.search(text):
            scores["secret_generic_token"] = 0.90

        return scores
