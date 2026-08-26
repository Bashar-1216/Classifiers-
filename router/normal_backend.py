"""
Normal Backend — Proxy for the normal AI cloud flow via Groq / OpenAI API.

Forwards requests to the configured cloud AI backend (Groq Cloud API)
when the Policy Decision routes them to NORMAL.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class NormalBackend:
    """
    Proxies requests to the configured Groq / OpenAI-compatible cloud backend.

    Uses httpx.AsyncClient for async HTTP communication with
    connection pooling and timeout management.
    """

    def __init__(
        self,
        backend_url: str = "https://api.groq.com/openai/v1",
        api_key: str | None = None,
        default_model: str = "openai/gpt-oss-120b",
        timeout: int = 60,
    ) -> None:
        self.backend_url = backend_url.rstrip("/")
        self.api_key = api_key
        self.default_model = default_model
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(
                    max_keepalive_connections=20,
                    max_connections=50,
                ),
            )
        return self._client

    def _build_url(self) -> str:
        """Resolve the full chat completions URL dynamically."""
        if self.backend_url.endswith("/chat/completions"):
            return self.backend_url
        elif self.backend_url.endswith("/v1"):
            return f"{self.backend_url}/chat/completions"
        else:
            return f"{self.backend_url}/v1/chat/completions"

    async def send(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        """
        Send a chat completion request to the Groq cloud backend.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            **kwargs: Additional parameters (model, temperature, max_tokens, etc.)

        Returns:
            OpenAI-compatible response dict from the Groq backend.
        """
        client = await self._get_client()
        model = kwargs.get("model") or self.default_model

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }
        for key in ("temperature", "max_tokens"):
            if key in kwargs and kwargs[key] is not None:
                payload[key] = kwargs[key]

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        url = self._build_url()
        logger.info("Normal backend (Groq) request to %s (model=%s, %d messages)", url, model, len(messages))

        try:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()
            logger.info("Normal backend (Groq) response: status=%d", response.status_code)
            return result

        except httpx.TimeoutException:
            logger.error("Groq backend timeout after %ds", self.timeout)
            raise
        except httpx.HTTPStatusError as e:
            logger.error("Groq backend HTTP error: %d — %s", e.response.status_code, e.response.text)
            raise
        except httpx.ConnectError as e:
            logger.error("Groq backend connection error: %s", e)
            raise

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            logger.info("Normal backend client closed")
