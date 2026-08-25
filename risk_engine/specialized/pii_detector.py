from __future__ import annotations

import logging
import re
from typing import Dict, List

logger = logging.getLogger(__name__)


class PIIDetector:
    """
    Personally Identifiable Information (PII) Detector.
    Uses three layers:
    1. Regex Pattern Matching (CC with Luhn, SSN, Email, Phone, IP, IBAN)
    2. Entity Context Scoring (Structured patterns, co-occurrence)
    3. Credential Detection (Keys, tokens, connection strings)
    """

    # Layer 1 Regex
    FORMATTED_CC_REGEX = re.compile(r"\b(?:\d{4}[-\s]){3}\d{4}\b")
    RAW_CC_REGEX = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"  # Visa
        r"5[1-5][0-9]{14}|"  # MasterCard
        r"2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[01][0-9]|720)[0-9]{12}|"  # MasterCard (2017+)
        r"3[47][0-9]{13})\b"  # Amex
    )
    SSN_REGEX = re.compile(r"\b(?!(?:000|666|9))\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    # Matches Int'l prefixes, specifically targeting +966, +971, +20, +962, +964, +961 and generic
    PHONE_REGEX = re.compile(
        r"(?:\+|00)(?:966|971|20|962|964|961|1|44)[ \-\.]?[0-9]{7,12}\b|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"
    )
    PRIVATE_IP_REGEX = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    )
    IBAN_REGEX = re.compile(r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[a-zA-Z0-9]){11,28}\b")

    # Layer 2 Context Regex
    CONTEXT_RECORD_REGEX = re.compile(
        r"(?i)(name|email|phone|address|ssn|dob|patient|customer|employee)\s*[:=]\s*\w+"
    )

    # Layer 3 Credentials Regex
    JWT_REGEX = re.compile(
        r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"
    )
    PRIVATE_KEY_REGEX = re.compile(
        r"-----BEGIN (?:RSA |DSA |EC |PGP |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |DSA |EC |PGP |OPENSSH )?PRIVATE KEY-----",
        re.DOTALL,
    )
    AWS_KEY_REGEX = re.compile(
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b"
    )
    AWS_SECRET_REGEX = re.compile(
        r"\b(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])\b"
    )
    BEARER_TOKEN_REGEX = re.compile(
        r"\bBearer [A-Za-z0-9\-._~+/]+=*\b", re.IGNORECASE
    )
    DB_CONN_REGEX = re.compile(
        r"\b(?:password|pwd|secret_key|api_key|token)\s*[=:]\s*[\'\"]?([a-zA-Z0-9!@#$%^&*()_+={}\[\]|\\:;\"\'<>,.?/~`\-]{8,})[\'\"]?\b",
        re.IGNORECASE,
    )

    def _luhn_check(self, card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm.
        """
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) < 13:
            return False

        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    def _evaluate_layer1_regex(self, text: str) -> Dict[str, float]:
        """
        Layer 1: Regex Pattern Matching.
        Detects standard deterministic formats like CC, SSN, IP, IBAN, Email, Phone.
        """
        scores: Dict[str, float] = {}

        # Check formatted and raw credit cards
        all_cc_candidates: List[str] = self.FORMATTED_CC_REGEX.findall(text)
        all_cc_candidates.extend(self.RAW_CC_REGEX.findall(text))

        valid_ccs = [cc for cc in all_cc_candidates if self._luhn_check(cc)]
        if valid_ccs:
            scores["pii_credit_card"] = min(1.0, 0.85 + (len(valid_ccs) * 0.05))

        if self.SSN_REGEX.search(text):
            scores["pii_ssn"] = 0.95

        if self.EMAIL_REGEX.search(text):
            scores["pii_email"] = 0.80

        if self.PHONE_REGEX.search(text):
            scores["pii_phone"] = 0.75

        if self.PRIVATE_IP_REGEX.search(text):
            scores["pii_private_ip"] = 0.60

        if self.IBAN_REGEX.search(text):
            scores["pii_iban"] = 0.85

        return scores

    def _evaluate_layer2_context(
        self, text: str, layer1_scores: Dict[str, float]
    ) -> Dict[str, float]:
        """
        Layer 2: Entity Context Scoring.
        Looks for structured records or dense presence of PII-related terms.
        """
        scores: Dict[str, float] = {}
        text_lower = text.lower()

        # Check structured record
        structured_matches = self.CONTEXT_RECORD_REGEX.findall(text)
        if len(structured_matches) >= 2:
            scores["pii_structured_record"] = min(
                1.0, 0.6 + (len(structured_matches) * 0.1)
            )

        # Co-occurrence density check
        entities_present = 0
        for kw in [
            "name",
            "email",
            "phone",
            "address",
            "patient",
            "customer",
            "employee",
        ]:
            if kw in text_lower:
                entities_present += 1

        if entities_present >= 3 and (
            "pii_email" in layer1_scores or "pii_phone" in layer1_scores
        ):
            scores["pii_context_density"] = min(
                1.0, 0.5 + (entities_present * 0.1)
            )

        return scores

    def _evaluate_layer3_credentials(self, text: str) -> Dict[str, float]:
        """
        Layer 3: Credential Detection.
        Detects keys, tokens, JWTs, and db connection passwords.
        """
        scores: Dict[str, float] = {}

        if self.PRIVATE_KEY_REGEX.search(text):
            scores["pii_credential_private_key"] = 1.0

        if self.JWT_REGEX.search(text):
            scores["pii_credential_jwt"] = 0.90

        if self.AWS_KEY_REGEX.search(text):
            scores["pii_credential_aws_key"] = 0.95

        if self.AWS_SECRET_REGEX.search(text):
            scores["pii_credential_aws_secret"] = 0.90

        if self.BEARER_TOKEN_REGEX.search(text):
            scores["pii_credential_bearer"] = 0.95

        if self.DB_CONN_REGEX.search(text):
            scores["pii_credential_db_conn"] = 0.85

        return scores

    def evaluate(self, text: str) -> Dict[str, float]:
        """
        Returns category-to-score mappings like:
        {'pii_credit_card': 0.95, 'pii_email': 0.80, 'pii_credential': 0.90, 'pii_structured_record': 0.75}
        Scores are 0.0 to 1.0. Only include categories with score > 0.
        """
        logger.debug("Evaluating text for PII")
        if not text:
            return {}

        final_scores: Dict[str, float] = {}

        # Run 3 layers
        l1_scores = self._evaluate_layer1_regex(text)
        final_scores.update(l1_scores)

        l2_scores = self._evaluate_layer2_context(text, l1_scores)
        final_scores.update(l2_scores)

        l3_scores = self._evaluate_layer3_credentials(text)
        final_scores.update(l3_scores)

        # Consolidate generic pii_credential if any layer 3 rule matched
        if any(k.startswith("pii_credential_") for k in final_scores):
            max_cred = max(
                v
                for k, v in final_scores.items()
                if k.startswith("pii_credential_")
            )
            final_scores["pii_credential"] = max_cred

        # Filter valid scores
        return {
            k: min(1.0, max(0.0, v)) for k, v in final_scores.items() if v > 0.0
        }
