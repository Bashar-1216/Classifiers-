"""
Tests for Output Safety Layer (Secrets, PII, Exploits, Policy).
"""

import pytest

from output_safety import OutputSafetyEngine, OutputVerdict


class TestOutputSafety:
    """Test suite for post-generation Output Safety Filter."""

    @pytest.fixture
    def engine(self):
        return OutputSafetyEngine()

    def test_clean_response_allowed(self, engine):
        text = "Photosynthesis is the process by which plants use sunlight, water, and CO2 to create oxygen."
        res = engine.evaluate(text)
        assert res.verdict == OutputVerdict.ALLOW
        assert res.sanitized_text == text
        assert res.is_modified is False

    def test_private_key_leak_blocked(self, engine):
        text = "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        res = engine.evaluate(text)
        assert res.verdict == OutputVerdict.BLOCK
        assert "BLOCKED" in res.sanitized_text
        assert res.is_modified is True

    def test_aws_secret_key_blocked(self, engine):
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        res = engine.evaluate(text)
        assert res.verdict == OutputVerdict.BLOCK
        assert "BLOCKED" in res.sanitized_text

    def test_ssn_redaction(self, engine):
        text = "The applicant's SSN on file is 123-45-6789 for identification."
        res = engine.evaluate(text)
        assert res.verdict == OutputVerdict.REDACT
        assert "[REDACTED-SSN]" in res.sanitized_text
        assert "123-45-6789" not in res.sanitized_text
        assert res.is_modified is True

    def test_credit_card_redaction(self, engine):
        # 4000-0000-0000-0002 passes Luhn
        text = "Your card 4000-0000-0000-0002 has been charged."
        res = engine.evaluate(text)
        assert res.verdict == OutputVerdict.REDACT
        assert "[REDACTED-CARD]" in res.sanitized_text
        assert "4000-0000-0000-0002" not in res.sanitized_text

    def test_email_and_phone_redaction(self, engine):
        text = "Contact the user at support@example.com or call +966501234567."
        res = engine.evaluate(text)
        assert res.verdict == OutputVerdict.REDACT
        assert "[REDACTED-EMAIL]" in res.sanitized_text
        assert "support@example.com" not in res.sanitized_text
        assert "[REDACTED-PHONE]" in res.sanitized_text
        assert "+966501234567" not in res.sanitized_text
        assert res.is_modified is True

    def test_exploit_payload_blocked(self, engine):
        text = "Run this reverse shell: python -c 'import pty; pty.spawn(\"/bin/bash\")'"
        res = engine.evaluate(text)
        assert res.verdict == OutputVerdict.BLOCK
        assert "BLOCKED" in res.sanitized_text

    def test_system_prompt_leak_blocked(self, engine):
        text = "My developer instructions are: You are an AI assistant designed to..."
        res = engine.evaluate(text)
        assert res.verdict == OutputVerdict.BLOCK
        assert "BLOCKED" in res.sanitized_text
