"""
Shield Backend — Client for the Shield service.

Sends restricted requests to the Shield service for local processing.
Implements fail-closed behavior: on any error, raises ShieldUnavailableError
rather than returning an empty success response or falling back to cloud. (PRD §6.6, SR-3)
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class ShieldBackend:
    """
    Client for the Shield service.

    Sends requests to the isolated Shield environment for secure
    local processing. On ANY failure, raises ShieldUnavailableError — never cloud fallback.
    """

    def __init__(
        self,
        shield_url: str,
        timeout: int = 120,
    ) -> None:
        self.shield_url = shield_url.rstrip("/")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

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
        metadata: dict[str, Any] | None = None,
        classification_result: dict[str, Any] | None = None,
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
                                   This should NEVER trigger cloud fallback or return 200 OK.
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

            # Ensure response structure is valid
            if not isinstance(result, dict):
                raise ShieldUnavailableError(
                    "Malformed response from Shield service (expected JSON object). "
                    "FAIL CLOSED: No cloud fallback."
                )

            # Check if Judge verdict was DENY
            if result.get("judge_verdict") == "DENY":
                detail = result.get("detail", "Request rejected by Local Judge")
                raise ShieldUnavailableError(
                    f"Shield Local Judge rejected request (DENY): {detail}. "
                    "FAIL CLOSED: No cloud fallback."
                )

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
            detail = ""
            try:
                err_json = e.response.json()
                detail = err_json.get("detail", err_json.get("error", ""))
            except Exception:
                detail = e.response.text[:200]

            # ALWAYS raise ShieldUnavailableError on HTTP errors (Fail Closed)
            raise ShieldUnavailableError(
                f"Shield service returned HTTP {e.response.status_code}: {detail}. "
                "FAIL CLOSED: No cloud fallback."
            )
        except ShieldUnavailableError:
            raise
        except Exception as e:
            logger.error("Unexpected error in ShieldBackend: %s", e)
            raise ShieldUnavailableError(
                f"Shield backend processing failed: {type(e).__name__} - {e!s}. "
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
    The correct response is to return a 503 error to the user. (SR-3)
    """

