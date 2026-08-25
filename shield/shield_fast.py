"""
SofaShieldFast — Internal Secure Inference Gateway.

Acts as the internal secure gateway between the Shield service and local LLM instances.
Manages circuit breaker resilience, input validation, and secure non-cloud inference.
Operates strictly within an isolated network without external fallbacks.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from shield.config import ShieldConfig
from shield.models import CircuitState

logger = logging.getLogger(__name__)


class ShieldInferenceError(Exception):
    """Base exception for Shield inference gateway errors."""


class CircuitBreakerOpenError(ShieldInferenceError):
    """Raised when inference is attempted while the circuit breaker is OPEN."""


class ShieldRequestValidationError(ShieldInferenceError):
    """Raised when an incoming request fails validation constraints."""


class ShieldBackendError(ShieldInferenceError):
    """Raised when the local LLM backend encounters an error or is unreachable."""


class SofaShieldFast:
    """
    Internal Secure Inference Gateway.

    Wraps the local LLM inference endpoint with circuit breaker protection,
    request size validation, and metadata-only audit logging.
    """

    def __init__(self, config: ShieldConfig | None = None) -> None:
        """
        Initialize the SofaShieldFast gateway.

        Args:
            config: Shield service configuration (optional, defaults to standard ShieldConfig).
        """
        self.config = config or ShieldConfig()
        self.state: CircuitState = CircuitState.CLOSED
        self.failure_count: int = 0
        self.last_failure_time: float | None = None
        self.client: httpx.AsyncClient = httpx.AsyncClient(
            timeout=httpx.Timeout(float(self.config.request_timeout)),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
        )
        logger.info(
            "SofaShieldFast gateway initialized with local backend URL: %s, model: %s",
            self.config.local_llm_url,
            self.config.local_llm_model,
        )

    def validate_request(self, messages: list[dict[str, Any]]) -> None:
        """Validate request size against configured limit."""
        total_size = sum(len(str(m.get("content", ""))) for m in messages if isinstance(m, dict))
        if total_size > self.config.max_request_size:
            raise ShieldRequestValidationError(
                f"Request size {total_size} exceeds maximum allowed size of {self.config.max_request_size} characters"
            )

    def record_failure(self, exc: Exception | None = None) -> None:
        """Public helper to record an inference failure."""
        self._record_failure(exc or Exception("Inference failure"))

    def get_circuit_state(self) -> CircuitState:
        """
        Evaluate and return the current circuit breaker state.

        If the circuit is OPEN and the recovery timeout has elapsed,
        transitions state to HALF_OPEN to allow a probe request.

        Returns:
            Current CircuitState (CLOSED, OPEN, or HALF_OPEN).
        """
        if self.state == CircuitState.OPEN and self.last_failure_time is not None:
            elapsed = time.monotonic() - self.last_failure_time
            if elapsed >= self.config.circuit_breaker_recovery:
                logger.info(
                    "Circuit breaker recovery window elapsed (%.2fs >= %ds). Transitioning OPEN -> HALF_OPEN",
                    elapsed,
                    self.config.circuit_breaker_recovery,
                )
                self.state = CircuitState.HALF_OPEN
        return self.state

    def _record_failure(self, exc: Exception) -> None:
        """
        Record an inference failure and update circuit breaker state.

        Args:
            exc: The exception that caused the failure.
        """
        self.failure_count += 1
        self.last_failure_time = time.monotonic()

        if self.failure_count >= self.config.circuit_breaker_threshold or self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            logger.warning(
                "Circuit breaker state set to OPEN: failure_count=%d (threshold=%d), error=%s",
                self.failure_count,
                self.config.circuit_breaker_threshold,
                exc,
            )
        else:
            logger.warning(
                "Inference failure recorded: failure_count=%d/%d, error=%s",
                self.failure_count,
                self.config.circuit_breaker_threshold,
                exc,
            )

    def _record_success(self) -> None:
        """Record a successful inference and reset circuit breaker if in HALF_OPEN or recovering."""
        if self.state == CircuitState.HALF_OPEN:
            logger.info("Probe inference succeeded in HALF_OPEN state. Closing circuit breaker.")
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None
        elif self.state == CircuitState.CLOSED and self.failure_count > 0:
            logger.info("Inference succeeded in CLOSED state. Resetting failure count from %d to 0.", self.failure_count)
            self.failure_count = 0

    async def infer(self, messages: list[dict[str, Any]]) -> str:
        """
        Execute local LLM inference through the secure gateway.

        Pipeline:
        1. Check circuit breaker state (reject immediately if OPEN).
        2. Validate request size against configured limit.
        3. Call local LLM via httpx POST in OpenAI-compatible format.
        4. Handle timeouts and connection errors (fail closed, never cloud fallback).
        5. Reset circuit breaker on success.
        6. Log request/response metadata (excluding prompt/response content).

        Args:
            messages: List of message dictionaries with 'role' and 'content'.

        Returns:
            The generated response string from the local LLM.

        Raises:
            CircuitBreakerOpenError: When circuit is OPEN.
            ShieldRequestValidationError: When request size exceeds limit.
            ShieldBackendError: When local backend fails or cannot be reached.
        """
        # 1. Check circuit breaker
        current_state = self.get_circuit_state()
        if current_state == CircuitState.OPEN:
            logger.error("Inference rejected: Shield backend unavailable - circuit open")
            raise CircuitBreakerOpenError("Shield backend unavailable - circuit open")

        # 2. Validate request (size check)
        total_size = sum(len(str(m.get("content", ""))) for m in messages if isinstance(m, dict))
        if total_size > self.config.max_request_size:
            logger.warning(
                "Request rejected: size (%d chars) exceeds maximum allowed size (%d chars)",
                total_size,
                self.config.max_request_size,
            )
            raise ShieldRequestValidationError(
                f"Request size {total_size} exceeds maximum allowed size of {self.config.max_request_size} characters"
            )

        # 3. Prepare payload and call local LLM
        endpoint = f"{self.config.local_llm_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self.config.local_llm_model,
            "messages": messages,
        }

        start_time = time.perf_counter()
        try:
            response = await self.client.post(
                url=endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=float(self.config.request_timeout),
            )
            response.raise_for_status()
            data = response.json()

        except httpx.TimeoutException as exc:
            self._record_failure(exc)
            logger.error("Local LLM request timed out after %ds: %s", self.config.request_timeout, exc)
            raise ShieldBackendError(f"Local LLM backend request timed out: {exc}") from exc

        except (httpx.ConnectError, httpx.NetworkError) as exc:
            self._record_failure(exc)
            logger.error("Local LLM connection error: %s", exc)
            raise ShieldBackendError(f"Failed to connect to local LLM backend: {exc}") from exc

        except httpx.HTTPStatusError as exc:
            self._record_failure(exc)
            logger.error("Local LLM backend returned HTTP error status %d", exc.response.status_code)
            raise ShieldBackendError(
                f"Local LLM backend returned HTTP {exc.response.status_code}"
            ) from exc

        except Exception as exc:
            self._record_failure(exc)
            logger.error("Unexpected error during local LLM backend inference: %s", exc)
            raise ShieldBackendError(f"Local LLM backend inference failed: {exc}") from exc

        # 4 & 5. Handle successful response
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        self._record_success()

        # Extract completion content
        choices = data.get("choices", [])
        if not choices or not isinstance(choices, list):
            logger.error("Local LLM response missing 'choices' array")
            raise ShieldBackendError("Invalid response format from local LLM backend: missing 'choices'")

        first_choice = choices[0]
        if not isinstance(first_choice, dict) or "message" not in first_choice:
            logger.error("Local LLM choice missing 'message' object")
            raise ShieldBackendError("Invalid response format from local LLM backend: missing 'message'")

        msg_obj = first_choice["message"]
        response_text = msg_obj.get("content", "")
        if not isinstance(response_text, str):
            response_text = str(response_text)

        # 6. Log metadata only (NO message content logged for privacy and security)
        usage = data.get("usage", {})
        logger.info(
            "Local LLM inference succeeded: model=%s, latency=%.2fms, messages_count=%d, prompt_chars=%d, response_chars=%d, prompt_tokens=%s, completion_tokens=%s",
            self.config.local_llm_model,
            duration_ms,
            len(messages),
            total_size,
            len(response_text),
            usage.get("prompt_tokens", "N/A"),
            usage.get("completion_tokens", "N/A"),
        )

        return response_text

    async def close(self) -> None:
        """Close the underlying HTTP client connection pool."""
        if self.client and not self.client.is_closed:
            await self.client.aclose()
            logger.info("SofaShieldFast HTTP client closed.")
