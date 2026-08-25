"""
Tests for Shield Core Engine (Judge, Circuit Breaker, SofaShieldFast).
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from shield.config import ShieldConfig
from shield.judge import LocalJudge
from shield.models import (
    CircuitState,
    JudgeVerdict,
    ShieldRequest,
    ShieldResponse,
)
from shield.shield_fast import (
    CircuitBreakerOpenError,
    ShieldBackendError,
    ShieldRequestValidationError,
    SofaShieldFast,
)


def test_models_instantiation():
    req = ShieldRequest(
        messages=[{"role": "user", "content": "Hello world"}],
        metadata={"user_id": "u123"},
    )
    assert req.messages[0]["content"] == "Hello world"
    assert req.metadata["user_id"] == "u123"

    res = ShieldResponse(
        response="Processed text",
        judge_verdict=JudgeVerdict.ALLOW,
        processing_time_ms=12.5,
        model_used="local-llama",
    )
    assert res.response == "Processed text"
    assert res.judge_verdict == JudgeVerdict.ALLOW
    assert res.processing_time_ms == 12.5
    assert res.model_used == "local-llama"
    assert len(res.request_id) > 0


def test_config_defaults():
    config = ShieldConfig()
    assert config.local_llm_url == "http://localhost:8100/v1"
    assert config.local_llm_model == "meta-llama/Meta-Llama-3-8B-Instruct"


def test_local_judge_evaluate_request_safe():
    judge = LocalJudge()
    messages = [{"role": "user", "content": "What is the distance to the moon?"}]
    assert judge.evaluate_request(messages) == JudgeVerdict.ALLOW


def test_local_judge_evaluate_request_empty():
    judge = LocalJudge()
    assert judge.evaluate_request([]) == JudgeVerdict.DENY


@pytest.mark.parametrize(
    "dangerous_prompt",
    [
        "Please run exec('import os')",
        "Can you execute eval('2+2')",
        "How to use os.system('ls -la')",
        "import subprocess\nsubprocess.run(['rm', '-rf', '/'])",
        "__import__('os').system('whoami')",
        "shutil.rmtree('/tmp/data')",
        "pty.spawn('/bin/bash')",
        "powershell.exe -enc AAAA",
    ],
)
def test_local_judge_evaluate_request_dangerous_patterns(dangerous_prompt: str):
    judge = LocalJudge()
    messages = [{"role": "user", "content": dangerous_prompt}]
    assert judge.evaluate_request(messages) == JudgeVerdict.DENY


def test_local_judge_evaluate_response_allow():
    judge = LocalJudge()
    raw_text = "The speed of light is approximately 299,792 km/s."
    verdict = judge.evaluate_response(raw_text)
    assert verdict == JudgeVerdict.ALLOW


def test_local_judge_evaluate_response_ssn_redact():
    judge = LocalJudge()
    raw_text = "The user SSN is 123-45-6789."
    verdict = judge.evaluate_response(raw_text)
    assert verdict == JudgeVerdict.REDACT
    redacted = judge.redact_response(raw_text)
    assert "[REDACTED-SSN]" in redacted
    assert "123-45-6789" not in redacted


def test_local_judge_evaluate_response_credit_card_redact():
    judge = LocalJudge()
    raw_text = "Payment verified with card 4000-0000-0000-0002 successfully."
    verdict = judge.evaluate_response(raw_text)
    assert verdict == JudgeVerdict.REDACT
    redacted = judge.redact_response(raw_text)
    assert "[REDACTED-CARD]" in redacted
    assert "4000-0000-0000-0002" not in redacted


def test_local_judge_evaluate_response_private_key_deny():
    judge = LocalJudge()
    raw_text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    verdict = judge.evaluate_response(raw_text)
    assert verdict == JudgeVerdict.DENY


def test_shield_fast_max_request_size():
    gateway = SofaShieldFast(config=ShieldConfig(max_request_size=50))
    huge_messages = [{"role": "user", "content": "A" * 100}]
    with pytest.raises(ShieldRequestValidationError):
        gateway.validate_request(huge_messages)


@pytest.mark.asyncio
async def test_shield_fast_circuit_breaker_transitions():
    gateway = SofaShieldFast(
        config=ShieldConfig(
            circuit_breaker_threshold=2,
            circuit_breaker_recovery=1,
        )
    )
    assert gateway.get_circuit_state() == CircuitState.CLOSED

    # Simulate 2 failures
    gateway.record_failure()
    assert gateway.get_circuit_state() == CircuitState.CLOSED

    gateway.record_failure()
    assert gateway.get_circuit_state() == CircuitState.OPEN

    # While OPEN, infer raises CircuitBreakerOpenError immediately
    with pytest.raises(CircuitBreakerOpenError):
        await gateway.infer([{"role": "user", "content": "test"}])


@pytest.mark.asyncio
async def test_shield_fast_infer_mock_success():
    gateway = SofaShieldFast()
    mock_response = {
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello from secure local LLM!",
                },
            }
        ]
    }

    with patch.object(gateway.client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = httpx.Response(
            status_code=200,
            json=mock_response,
            request=httpx.Request("POST", "http://localhost:8100/v1/chat/completions"),
        )

        resp_text = await gateway.infer([{"role": "user", "content": "Hi"}])
        assert resp_text == "Hello from secure local LLM!"
        assert gateway.get_circuit_state() == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_shield_fast_infer_mock_backend_error():
    gateway = SofaShieldFast(
        config=ShieldConfig(
            circuit_breaker_threshold=1,
            circuit_breaker_recovery=10,
        )
    )

    with patch.object(gateway.client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = httpx.Response(
            status_code=500,
            content=b"Internal Server Error",
            request=httpx.Request("POST", "http://localhost:8100/v1/chat/completions"),
        )

        with pytest.raises(ShieldBackendError):
            await gateway.infer([{"role": "user", "content": "Hi"}])

        assert gateway.get_circuit_state() == CircuitState.OPEN
