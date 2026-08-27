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

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class LocalJudge:
    """
    Deterministic safety evaluator for isolated Shield processing using declarative security knowledge.

    Evaluates:
    - Pre-LLM: Validates messages and detects dangerous code injection or command execution patterns.
    - Post-LLM: Detects critical secret leaks (DENY) or PII patterns (REDACT).
    """

    def __init__(self) -> None:
        """Initialize the Local Judge using SecurityKnowledgeBundle."""
        bundle = KnowledgeLoader.get_bundle()

        # Dangerous request execution patterns (from SEC-RULE-010 and related rules)
        self.dangerous_request_patterns: list[re.Pattern[str]] = []
        for r in bundle.ingress_rules:
            if "execution" in r.name or "exploit" in r.name or "exploit" in r.category:
                for p in r.patterns:
                    self.dangerous_request_patterns.append(re.compile(p, re.IGNORECASE))

        # Critical secret patterns (from bundle.secret_dlp_patterns)
        self.critical_secret_patterns: list[re.Pattern[str]] = []
        for entry in bundle.secret_dlp_patterns:
            self.critical_secret_patterns.extend(entry.get("compiled_patterns", []))

        # PII patterns (from bundle.pii_dlp_patterns)
        self.pii_patterns: list[dict[str, Any]] = bundle.pii_dlp_patterns
        self.ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
        self.email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        self.credit_card_patterns: list[re.Pattern[str]] = []

        for entry in self.pii_patterns:
            p_id = entry.get("id", "")
            comp = entry.get("compiled_patterns", [])
            if "CREDIT-CARD" in p_id or "credit_card" in entry.get("category", ""):
                self.credit_card_patterns.extend(comp)
            elif "SSN" in p_id and comp:
                self.ssn_pattern = comp[0]
            elif "EMAIL" in p_id and comp:
                self.email_pattern = comp[0]

        logger.info("LocalJudge initialized with declarative security knowledge (Isolated mode)")

    def evaluate_request(self, messages: list[dict[str, Any]]) -> JudgeVerdict:
        """
        Pre-LLM validation and safety check.
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
            for pattern in self.dangerous_request_patterns:
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
        """
        if not response_text or not isinstance(response_text, str):
            return JudgeVerdict.ALLOW

        # 1. Critical secret check (DENY)
        for pattern in self.critical_secret_patterns:
            if pattern.search(response_text):
                logger.warning("LocalJudge: Response rejected (DENY) due to exposed critical secret")
                return JudgeVerdict.DENY

        # 2. PII checks (REDACT)
        if self.ssn_pattern.search(response_text):
            logger.info("LocalJudge: SSN pattern detected in response, verdict=REDACT")
            return JudgeVerdict.REDACT

        if self.email_pattern.search(response_text):
            logger.info("LocalJudge: Email pattern detected in response, verdict=REDACT")
            return JudgeVerdict.REDACT

        for pattern in self.credit_card_patterns:
            if pattern.search(response_text):
                logger.info("LocalJudge: Credit card pattern detected in response, verdict=REDACT")
                return JudgeVerdict.REDACT

        return JudgeVerdict.ALLOW

    def redact_response(self, response_text: str) -> str:
        """
        Sanitize and mask sensitive PII (SSNs, emails, credit cards) in response text.
        """
        if not response_text:
            return response_text

        redacted = self.ssn_pattern.sub("[REDACTED-SSN]", response_text)
        redacted = self.email_pattern.sub("[REDACTED-EMAIL]", redacted)
        for pattern in self.credit_card_patterns:
            redacted = pattern.sub("[REDACTED-CARD]", redacted)

        return redacted
