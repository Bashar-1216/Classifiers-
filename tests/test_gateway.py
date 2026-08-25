"""
Gateway tests — PRD §6.1.

Tests:
- Authentication: valid key, invalid key, missing key
- Rate limiting: under limit, over limit
- Health checks
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from gateway.main import app


# client fixture is provided by conftest.py with lifespan


class TestAuthentication:
    """Test API key authentication."""

    def test_valid_api_key(self, client: TestClient) -> None:
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": "Bearer sk-test-key-1"},
        )
        # Should not be 401 (may be 503 if no backend, but auth passed)
        assert response.status_code != 401

    def test_invalid_api_key(self, client: TestClient) -> None:
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": "Bearer invalid-key"},
        )
        assert response.status_code == 401

    def test_missing_auth_header(self, client: TestClient) -> None:
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
        )
        assert response.status_code == 401

    def test_malformed_auth_header(self, client: TestClient) -> None:
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": "Token sk-test-key-1"},
        )
        assert response.status_code == 401

    def test_empty_bearer_token(self, client: TestClient) -> None:
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": "Bearer "},
        )
        assert response.status_code == 401


class TestHealthChecks:
    """Test health check endpoints (no auth required)."""

    def test_liveness(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"

    def test_readiness(self, client: TestClient) -> None:
        response = client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "components" in data


class TestRateLimiting:
    """Test rate limiting enforcement."""

    def test_under_limit_passes(self, client: TestClient) -> None:
        """A single request should pass rate limiting."""
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": "Bearer sk-test-key-1"},
        )
        assert response.status_code != 429

    def test_health_not_rate_limited(self, client: TestClient) -> None:
        """Health endpoints should never be rate limited."""
        for _ in range(100):
            response = client.get("/health")
            assert response.status_code == 200


class TestRequestValidation:
    """Test request body validation."""

    def test_empty_body(self, client: TestClient) -> None:
        response = client.post(
            "/v1/chat/completions",
            json={},
            headers={"Authorization": "Bearer sk-test-key-1"},
        )
        # Should accept (messages defaults to empty list)
        assert response.status_code != 422

    def test_invalid_message_format(self, client: TestClient) -> None:
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"wrong_field": "bad"}]},
            headers={"Authorization": "Bearer sk-test-key-1"},
        )
        assert response.status_code == 422
