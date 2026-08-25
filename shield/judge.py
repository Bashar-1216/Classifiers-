"""
Local Judge — Request and Response Safety Evaluation.

Performs deterministic, rule-based safety evaluation on incoming requests (pre-LLM)
and generated responses (post-LLM) within an isolated, air-gapped environment.
Operates with zero internet connectivity and zero external tool calls.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from shield.models import JudgeVerdict

logger = logging.getLogger(__name__)


class LocalJudge:
    """
    Deterministic safety evaluator for isolated Shield processing.

    Evaluates:
    - Pre-LLM: Validates messages and detects dangerous code injection or command execution patterns.
    - Post-LLM: Detects critical secret leaks (DENY) or PII patterns (REDACT).
    """

    # Pre-compiled dangerous request patterns (code injection, command execution, shell exploits)
    DANGEROUS_REQUEST_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"\bexec\s*\(", re.IGNORECASE),
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
        re.compile(r"\bos\.popen\s*\(", re.IGNORECASE),
        re.compile(r"\bsubprocess(?:\.Popen|\.run|\.call|\.check_output|\.getoutput)?\b", re.IGNORECASE),
        re.compile(r"\b__import__\s*\(", re.IGNORECASE),
        re.compile(r"\bshutil\.rmtree\b", re.IGNORECASE),
        re.compile(r"\bpty\.spawn\b", re.IGNORECASE),
        re.compile(r"/bin/(?:bash|sh|zsh)\b", re.IGNORECASE),
        re.compile(r"\bcmd\.exe\b", re.IGNORECASE),
        re.compile(r"\bpowershell(?:\.exe)?\s+-(?:e|enc|encodedcommand|c|command)\b", re.IGNORECASE),
    ]

    # Pre-compiled critical secret patterns in response (triggers DENY)
    CRITICAL_SECRET_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        re.compile(r"(?i)\b(?:aws_secret_access_key|private_key)\s*[:=]\s*[A-Za-z0-9/+=]{20,}"),
    ]

    # Pre-compiled PII patterns in response (triggers REDACT)
    SSN_PATTERN: re.Pattern[str] = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    CREDIT_CARD_PATTERNS: list[re.Pattern[str]] = [
        # Formatted 16-digit card numbers (e.g. 1234-5678-9012-3456 or 1234 5678 9012 3456)
        re.compile(r"\b(?:\d{4}[-\s]){3}\d{4}\b"),
        # Visa
        re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),
        # MasterCard
        re.compile(r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b"),
        # American Express
        re.compile(r"\b3[47][0-9]{13}\b"),
        # Unformatted 16-digit numbers
        re.compile(r"\b\d{16}\b"),
    ]

    def __init__(self) -> None:
        """Initialize the Local Judge."""
        logger.info("LocalJudge initialized with deterministic safety rules (Isolated mode)")

    def evaluate_request(self, messages: list[dict[str, Any]]) -> JudgeVerdict:
        """
        Pre-LLM validation and safety check.

        Validates that messages list is non-empty and checks message contents
        against dangerous execution patterns (e.g. exec, os.system, subprocess).

        Args:
            messages: List of message dictionaries with 'role' and 'content'.

        Returns:
            JudgeVerdict.ALLOW if safe, or JudgeVerdict.DENY if invalid or dangerous.
        """
        if not messages or not isinstance(messages, list):
            logger.warning("LocalJudge: Empty or invalid messages list received")
            return JudgeVerdict.DENY

        has_valid_content = False

        for idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                logger.warning("LocalJudge: Message at index %d is not a dict", idx)
                return JudgeVerdict.DENY

            content = msg.get("content")
            if content is None:
                continue

            content_str = str(content)
            if content_str.strip():
                has_valid_content = True

            # Check for executable code injection and dangerous shell commands
            for pattern in self.DANGEROUS_REQUEST_PATTERNS:
                if pattern.search(content_str):
                    logger.warning(
                        "LocalJudge: Request rejected (DENY) due to dangerous pattern match at message %d",
                        idx,
                    )
                    return JudgeVerdict.DENY

        if not has_valid_content:
            logger.warning("LocalJudge: Request contains no valid non-empty message content")
            return JudgeVerdict.DENY

        return JudgeVerdict.ALLOW

    def evaluate_response(self, response_text: str) -> JudgeVerdict:
        """
        Post-LLM safety evaluation.

        Checks response text for critical secret leaks (DENY) or PII patterns (REDACT).

        Args:
            response_text: Raw response string from the local LLM.

        Returns:
            JudgeVerdict: ALLOW, REDACT, or DENY.
        """
        if not response_text or not isinstance(response_text, str):
            return JudgeVerdict.ALLOW

        # 1. Critical secret check (DENY)
        for pattern in self.CRITICAL_SECRET_PATTERNS:
            if pattern.search(response_text):
                logger.warning("LocalJudge: Response rejected (DENY) due to exposed critical secret")
                return JudgeVerdict.DENY

        # 2. PII checks (REDACT)
        # SSN check
        if self.SSN_PATTERN.search(response_text):
            logger.info("LocalJudge: SSN pattern detected in response, verdict=REDACT")
            return JudgeVerdict.REDACT

        # Credit card check
        for pattern in self.CREDIT_CARD_PATTERNS:
            if pattern.search(response_text):
                logger.info("LocalJudge: Credit card pattern detected in response, verdict=REDACT")
                return JudgeVerdict.REDACT

        return JudgeVerdict.ALLOW

    def redact_response(self, response_text: str) -> str:
        """
        Sanitize and mask sensitive PII (SSNs and credit cards) in response text.

        Args:
            response_text: Text containing sensitive PII.

        Returns:
            Sanitized text with PII replaced with redaction placeholders.
        """
        if not response_text:
            return response_text

        redacted = self.SSN_PATTERN.sub("[REDACTED-SSN]", response_text)
        for pattern in self.CREDIT_CARD_PATTERNS:
            redacted = pattern.sub("[REDACTED-CARD]", redacted)

        return redacted
