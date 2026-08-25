"""
Bypass prevention tests — PRD §11, SR-1.

Tests that direct access to backends is denied.
Only the Gateway path is allowed.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

# client fixture is provided by conftest.py with lifespan


class TestNoBypass:
    """
    Verify that all requests must go through Gateway.

    The Gateway enforces authentication on all non-health endpoints.
    Direct access without auth = denied.
    """

    def test_chat_without_auth_denied(self, client: TestClient) -> None:
        """Direct API call without authentication → 401."""
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
        )
        assert response.status_code == 401

    def test_chat_with_wrong_auth_denied(self, client: TestClient) -> None:
        """Direct API call with wrong key → 401."""
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert response.status_code == 401

    def test_nonexistent_endpoint_denied(self, client: TestClient) -> None:
        """Access to non-existent endpoints → 404 or 405."""
        response = client.post(
            "/v1/direct/llm",
            json={"prompt": "bypass"},
            headers={"Authorization": "Bearer sk-test-key-1"},
        )
        assert response.status_code in (404, 405)

    def test_shield_endpoint_not_exposed_on_gateway(self, client: TestClient) -> None:
        """Shield's internal endpoint should not exist on Gateway."""
        response = client.post(
            "/v1/shield/process",
            json={"messages": [{"role": "user", "content": "test"}]},
            headers={"Authorization": "Bearer sk-test-key-1"},
        )
        assert response.status_code in (404, 405)

    def test_only_gateway_path_works(self, client: TestClient) -> None:
        """Only /v1/chat/completions with valid auth is the allowed path."""
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": "Bearer sk-test-key-1"},
        )
        # Should not be 401 or 404 (may be 503 if backends aren't up)
        assert response.status_code not in (401, 404)
