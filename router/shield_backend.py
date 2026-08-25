"""
Shield Backend — Client for the Shield service.

Sends restricted requests to the Shield service for local processing.
Implements fail-closed behavior: on any error, returns an error
rather than falling back to cloud. (PRD §6.6, SR-3)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class ShieldBackend:
    """
    Client for the Shield service.

    Sends requests to the isolated Shield environment for secure
    local processing. On ANY failure, returns error — never cloud fallback.
    """

    def __init__(
        self,
        shield_url: str,
        timeout: int = 120,
    ) -> None:
        self.shield_url = shield_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
            )
        return self._client

    async def send(
        self,
        messages: list[dict[str, str]],
        metadata: Optional[dict[str, Any]] = None,
        classification_result: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Send a restricted request to the Shield service for local processing.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            metadata: Optional request metadata.
            classification_result: The classification that triggered shield routing.

        Returns:
            Response dict from the Shield service.

        Raises:
            ShieldUnavailableError: When Shield service cannot process the request.
                                   This should NEVER trigger cloud fallback.
        """
        client = await self._get_client()

        payload: dict[str, Any] = {
            "messages": messages,
        }
        if metadata:
            payload["metadata"] = metadata
        if classification_result:
            payload["classification_result"] = classification_result

        url = f"{self.shield_url}/v1/shield/process"

        logger.info("Shield backend request to %s (%d messages)", url, len(messages))

        try:
            response = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            result = response.json()
            logger.info(
                "Shield backend response: status=%d, verdict=%s",
                response.status_code,
                result.get("judge_verdict", "unknown"),
            )
            return result

        except httpx.TimeoutException:
            logger.error("Shield backend timeout after %ds", self.timeout)
            raise ShieldUnavailableError(
                "Shield service timeout — request cannot be processed. "
                "FAIL CLOSED: No cloud fallback."
            )
        except httpx.ConnectError:
            logger.error("Shield backend connection refused at %s", self.shield_url)
            raise ShieldUnavailableError(
                "Shield service unavailable — cannot connect. "
                "FAIL CLOSED: No cloud fallback."
            )
        except httpx.HTTPStatusError as e:
            logger.error(
                "Shield backend HTTP error: %d",
                e.response.status_code,
            )
            # Return the error response from shield (e.g., 403 from judge)
            try:
                return e.response.json()
            except Exception:
                raise ShieldUnavailableError(
                    f"Shield service error (HTTP {e.response.status_code}). "
                    "FAIL CLOSED: No cloud fallback."
                )

    async def health_check(self) -> bool:
        """Check if the Shield service is healthy."""
        try:
            client = await self._get_client()
            response = await client.get(
                f"{self.shield_url}/health",
                timeout=5.0,
            )
            return response.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            logger.info("Shield backend client closed")


class ShieldUnavailableError(Exception):
    """
    Raised when the Shield service cannot process a request.

    This error must NEVER trigger a cloud fallback.
    The correct response is to return an error to the user. (SR-3)
    """

    pass
