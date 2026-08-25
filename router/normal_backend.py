"""
Normal Backend — Proxy for the normal AI flow.

Forwards requests to the configured cloud AI backend (e.g., OpenAI API)
when the Policy Decision routes them to NORMAL. (PRD §6.6)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class NormalBackend:
    """
    Proxies requests to the configured normal AI backend.

    Uses httpx.AsyncClient for async HTTP communication with
    connection pooling and timeout management.
    """

    def __init__(
        self,
        backend_url: str,
        api_key: Optional[str] = None,
        default_model: str = "gemini-1.5-flash",
        timeout: int = 60,
    ) -> None:
        self.backend_url = backend_url.rstrip("/")
        self.api_key = api_key
        self.default_model = default_model
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

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
        elif self.backend_url.endswith(("/v1", "/openai", "/v1beta/openai")):
            return f"{self.backend_url}/chat/completions"
        else:
            return f"{self.backend_url}/v1/chat/completions"

    async def send(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        """
        Send a chat completion request to the normal backend.
        Supports both Google Gemini API and standard OpenAI-compatible endpoints.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            **kwargs: Additional parameters (model, temperature, max_tokens, etc.)

        Returns:
            OpenAI-compatible response dict from the backend.
        """
        client = await self._get_client()
        model = kwargs.get("model") or self.default_model

        # --- Branch 1: Google Gemini Native API ---
        if "generativelanguage.googleapis.com" in self.backend_url:
            return await self._send_gemini(client, messages, model, **kwargs)

        # --- Branch 2: Standard OpenAI-Compatible Endpoint ---
        return await self._send_openai(client, messages, model, **kwargs)

    async def _send_gemini(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
        model: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Format request and send to Google Gemini generateContent API."""
        # Ensure model has 'models/' prefix if needed
        model_name = model if model.startswith("models/") else f"models/{model}"
        url = f"https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent?key={self.api_key}"

        # Convert chat messages to Gemini contents format
        contents = []
        system_instruction = None

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                system_instruction = {"parts": [{"text": content}]}
            else:
                gemini_role = "model" if role == "assistant" else "user"
                contents.append({"role": gemini_role, "parts": [{"text": content}]})

        if not contents:
            contents.append({"role": "user", "parts": [{"text": "Hello"}]})

        payload: dict[str, Any] = {"contents": contents}
        if system_instruction:
            payload["system_instruction"] = system_instruction

        # Generation config
        gen_config: dict[str, Any] = {}
        if "temperature" in kwargs and kwargs["temperature"] is not None:
            gen_config["temperature"] = kwargs["temperature"]
        if "max_tokens" in kwargs and kwargs["max_tokens"] is not None:
            gen_config["maxOutputTokens"] = kwargs["max_tokens"]
        if gen_config:
            payload["generationConfig"] = gen_config

        logger.info("Normal backend (Gemini) request to %s (%d messages)", model_name, len(messages))

        try:
            response = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
            response.raise_for_status()
            data = response.json()

            # Extract generated text
            candidates = data.get("candidates", [])
            text = ""
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    text = parts[0].get("text", "")

            # Convert to OpenAI-compatible response format
            return {
                "id": f"chatcmpl-gemini-{data.get('modelVersion', 'v1')}",
                "object": "chat.completion",
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": data.get("usageMetadata", {}).get("promptTokenCount", 0),
                    "completion_tokens": data.get("usageMetadata", {}).get("candidatesTokenCount", 0),
                    "total_tokens": data.get("usageMetadata", {}).get("totalTokenCount", 0),
                },
            }

        except httpx.TimeoutException:
            logger.error("Gemini backend timeout after %ds", self.timeout)
            raise
        except httpx.HTTPStatusError as e:
            logger.error("Gemini backend HTTP error: %d — %s", e.response.status_code, e.response.text)
            raise
        except httpx.ConnectError as e:
            logger.error("Gemini backend connection error: %s", e)
            raise

    async def _send_openai(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
        model: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Send to standard OpenAI-compatible API endpoint."""
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
        logger.info("Normal backend (OpenAI) request to %s (model=%s, %d messages)", url, model, len(messages))

        try:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()
            logger.info("Normal backend response: status=%d", response.status_code)
            return result

        except httpx.TimeoutException:
            logger.error("Normal backend timeout after %ds", self.timeout)
            raise
        except httpx.HTTPStatusError as e:
            logger.error("Normal backend HTTP error: %d — %s", e.response.status_code, e)
            raise
        except httpx.ConnectError as e:
            logger.error("Normal backend connection error: %s", e)
            raise

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            logger.info("Normal backend client closed")
