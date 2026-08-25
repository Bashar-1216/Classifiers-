"""
Tests for Shield Service.

Covers models, configuration, LocalJudge, SofaShieldFast gateway with circuit breaker,
and the Shield FastAPI application.
"""

import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from shield.config import ShieldConfig
from shield.judge import LocalJudge
from shield.main import app
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

# ============================================================================
# 1. Models & Config Tests
# ============================================================================


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
    assert config.request_timeout == 120
    assert config.max_request_size == 10000
    assert config.circuit_breaker_threshold == 3
    assert config.circuit_breaker_recovery == 30
    assert config.host == "0.0.0.0"
    assert config.port == 8001
    assert config.log_level == "INFO"


# ============================================================================
# 2. LocalJudge Tests
# ============================================================================


def test_local_judge_evaluate_request_safe():
    judge = LocalJudge()
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Write a summary of classical mechanics."},
    ]
    assert judge.evaluate_request(messages) == JudgeVerdict.ALLOW


def test_local_judge_evaluate_request_empty():
    judge = LocalJudge()
    assert judge.evaluate_request([]) == JudgeVerdict.DENY
    assert judge.evaluate_request([{"role": "user", "content": "   "}]) == JudgeVerdict.DENY


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
    safe_response = "Here is an explanation of quantum entanglement without any secrets."
    assert judge.evaluate_response(safe_response) == JudgeVerdict.ALLOW


def test_local_judge_evaluate_response_ssn_redact():
    judge = LocalJudge()
    response_with_ssn = "Customer SSN is 123-45-6789 for identification."
    assert judge.evaluate_response(response_with_ssn) == JudgeVerdict.REDACT

    redacted = judge.redact_response(response_with_ssn)
    assert "123-45-6789" not in redacted
    assert "[REDACTED-SSN]" in redacted


def test_local_judge_evaluate_response_credit_card_redact():
    judge = LocalJudge()
    response_with_card = "Your payment card 4111-2222-3333-4444 was charged."
    assert judge.evaluate_response(response_with_card) == JudgeVerdict.REDACT

    redacted = judge.redact_response(response_with_card)
    assert "4111-2222-3333-4444" not in redacted
    assert "[REDACTED-CARD]" in redacted


def test_local_judge_evaluate_response_private_key_deny():
    judge = LocalJudge()
    response_with_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----"
    assert judge.evaluate_response(response_with_key) == JudgeVerdict.DENY


# ============================================================================
# 3. SofaShieldFast Gateway & Circuit Breaker Tests
# ============================================================================


@pytest.mark.asyncio
async def test_shield_fast_max_request_size():
    config = ShieldConfig(max_request_size=50)
    gateway = SofaShieldFast(config=config)
    try:
        large_msg = [{"role": "user", "content": "x" * 60}]
        with pytest.raises(ShieldRequestValidationError):
            await gateway.infer(large_msg)
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_shield_fast_circuit_breaker_transitions():
    config = ShieldConfig(
        circuit_breaker_threshold=2,
        circuit_breaker_recovery=1,  # 1 second recovery for test speed
    )
    gateway = SofaShieldFast(config=config)

    try:
        assert gateway.get_circuit_state() == CircuitState.CLOSED

        # Simulate failures
        gateway._record_failure(Exception("Error 1"))
        assert gateway.get_circuit_state() == CircuitState.CLOSED
        assert gateway.failure_count == 1

        gateway._record_failure(Exception("Error 2"))
        assert gateway.get_circuit_state() == CircuitState.OPEN
        assert gateway.failure_count == 2

        # While OPEN, infer raises CircuitBreakerOpenError
        with pytest.raises(CircuitBreakerOpenError) as exc_info:
            await gateway.infer([{"role": "user", "content": "test"}])
        assert "Shield backend unavailable - circuit open" in str(exc_info.value)

        # Wait for recovery window
        time.sleep(1.1)
        assert gateway.get_circuit_state() == CircuitState.HALF_OPEN

        # Success in HALF_OPEN restores CLOSED
        gateway._record_success()
        assert gateway.get_circuit_state() == CircuitState.CLOSED
        assert gateway.failure_count == 0
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_shield_fast_infer_mock_success():
    config = ShieldConfig()
    gateway = SofaShieldFast(config=config)

    mock_response = {
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "This is a secure local LLM response.",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 8},
    }

    try:
        with patch.object(gateway.client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = httpx.Response(
                status_code=200,
                json=mock_response,
                request=httpx.Request("POST", f"{config.local_llm_url}/chat/completions"),
            )

            result = await gateway.infer([{"role": "user", "content": "Hello"}])
            assert result == "This is a secure local LLM response."
            assert gateway.get_circuit_state() == CircuitState.CLOSED
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_shield_fast_infer_mock_backend_error():
    config = ShieldConfig(circuit_breaker_threshold=1)
    gateway = SofaShieldFast(config=config)

    try:
        with patch.object(gateway.client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.ConnectError("Connection refused")

            with pytest.raises(ShieldBackendError):
                await gateway.infer([{"role": "user", "content": "Hello"}])

            # Circuit should now be OPEN
            assert gateway.get_circuit_state() == CircuitState.OPEN
    finally:
        await gateway.close()


# ============================================================================
# 4. FastAPI Endpoint Tests
# ============================================================================


def test_fastapi_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert data["circuit_state"] in ["CLOSED", "OPEN", "HALF_OPEN"]
        assert data["service"] == "shield"


def test_fastapi_process_deny_by_judge():
    with TestClient(app) as client:
        response = client.post(
            "/v1/shield/process",
            json={"messages": [{"role": "user", "content": "os.system('id')"}]},
        )
        assert response.status_code == 403
        data = response.json()
        assert "rejected by local judge" in data.get("detail", "").lower()


def test_fastapi_process_safe_flow():
    with TestClient(app) as client:
        mock_response = {
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Quantum superposition is a fundamental principle.",
                    },
                }
            ]
        }

        shield_fast: SofaShieldFast = app.state.shield_fast
        with patch.object(shield_fast.client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = httpx.Response(
                status_code=200,
                json=mock_response,
                request=httpx.Request("POST", "http://localhost:8100/v1/chat/completions"),
            )

            response = client.post(
                "/v1/shield/process",
                json={"messages": [{"role": "user", "content": "Explain quantum superposition"}]},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["judge_verdict"] == "ALLOW"
            assert "Quantum superposition" in data["response"]
            assert data["processing_time_ms"] > 0
            assert "request_id" in data


def test_fastapi_process_redact_flow():
    with TestClient(app) as client:
        mock_response = {
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "User account verification SSN: 987-65-4321 confirmed.",
                    },
                }
            ]
        }

        shield_fast: SofaShieldFast = app.state.shield_fast
        with patch.object(shield_fast.client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = httpx.Response(
                status_code=200,
                json=mock_response,
                request=httpx.Request("POST", "http://localhost:8100/v1/chat/completions"),
            )

            response = client.post(
                "/v1/shield/process",
                json={"messages": [{"role": "user", "content": "Look up my user account details"}]},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["judge_verdict"] == "REDACT"
            assert "987-65-4321" not in data["response"]
            assert "[REDACTED-SSN]" in data["response"]


def test_fastapi_process_circuit_breaker_open():
    with TestClient(app) as client:
        shield_fast: SofaShieldFast = app.state.shield_fast
        shield_fast.state = CircuitState.OPEN
        shield_fast.last_failure_time = time.monotonic()

        response = client.post(
            "/v1/shield/process",
            json={"messages": [{"role": "user", "content": "Valid question"}]},
        )
        assert response.status_code == 503
        data = response.json()
        assert "circuit open" in data.get("detail", "").lower()

        # Reset state back to closed
        shield_fast.state = CircuitState.CLOSED
        shield_fast.failure_count = 0
        shield_fast.last_failure_time = None
