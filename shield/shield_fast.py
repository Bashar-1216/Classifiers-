"""
SofaShieldFast — Internal Secure Inference Gateway.

Acts as the internal secure gateway between the Shield service and local LLM instances.
Manages circuit breaker resilience, input validation, and secure non-cloud inference.
Operates strictly within an isolated network without external fallbacks.
Enforces Application-Level Air-Gap Guard when shield_mode is 'local_isolated'.
"""

from __future__ import annotations

import ipaddress
import logging
import time
import urllib.parse
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


class ShieldIsolationViolationError(ShieldInferenceError):
    """Raised when an illegal external/cloud URL is configured in isolated mode."""


class SofaShieldFast:
    """
    Internal Secure Inference Gateway.

    Wraps the local LLM inference endpoint with circuit breaker protection,
    request size validation, application-level air-gap isolation guards,
    and metadata-only audit logging.
    """

    ALLOWED_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "local_llm", "shield_fast"}

    def __init__(self, config: ShieldConfig | None = None) -> None:
        """
        Initialize the SofaShieldFast gateway.

        Args:
            config: Shield service configuration (optional, defaults to standard ShieldConfig).
        """
        self.config = config or ShieldConfig()

        # Enforce Application-Level Air-Gap Guard if running in isolated mode
        if self.config.shield_mode == "local_isolated":
            self._validate_isolation_guard(self.config.local_llm_url)

        self.state: CircuitState = CircuitState.CLOSED
        self.failure_count: int = 0
        self.last_failure_time: float | None = None

        # Build HTTP client with air-gap hardening:
        # - trust_env=False: Prevents proxy escape via HTTP_PROXY/HTTPS_PROXY env variables
        # - follow_redirects=False: Prevents 302 redirect escapes to external cloud hosts
        self.client: httpx.AsyncClient = httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(float(self.config.request_timeout)),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
        )
        logger.info(
            "SofaShieldFast gateway initialized in [%s] mode with local backend URL: %s, model: %s",
            self.config.shield_mode,
            self.config.local_llm_url,
            self.config.local_llm_model,
        )

    @classmethod
    def _validate_isolation_guard(cls, url: str) -> None:
        """
        Verify that the configured backend URL points strictly to loopback or local isolated container.
        Rejects public cloud hostnames, public IP addresses, and invalid schemes.
        """
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ShieldIsolationViolationError(f"Air-Gap Guard: Invalid scheme '{parsed.scheme}'. Must be http or https.")

        hostname = parsed.hostname or ""
        if not hostname:
            raise ShieldIsolationViolationError(f"Air-Gap Guard: No hostname found in URL: {url}")

        # Check explicit local allowlist
        if hostname.lower() in cls.ALLOWED_LOCAL_HOSTNAMES:
            return

        # Check IP address (must be loopback)
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback:
                return
            raise ShieldIsolationViolationError(
                f"Air-Gap Guard: Non-loopback IP address '{hostname}' is forbidden in isolated mode. "
                "Local inference must strictly use loopback (127.0.0.1, ::1) or local_llm container."
            )
        except ValueError:
            # Not a valid IP -> it's an unapproved external hostname (e.g. googleapis.com, openai.com)
            raise ShieldIsolationViolationError(
                f"Air-Gap Guard: Hostname '{hostname}' is not a permitted local backend. "
                "Cloud hostnames (e.g. googleapis.com, openai.com) are strictly forbidden in isolated mode."
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

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            data = response.json()

            # Extract generated content from standard OpenAI choices
            choices = data.get("choices", [])
            if not choices or not isinstance(choices, list):
                raise ShieldBackendError("Invalid response format from local LLM: missing 'choices'")

            first_choice = choices[0]
            message_obj = first_choice.get("message", {})
            content = message_obj.get("content")

            if content is None:
                raise ShieldBackendError("Invalid response format from local LLM: missing 'message.content'")

            self._record_success()
            logger.info(
                "Local LLM inference succeeded in %.2fms, finish_reason: %s",
                duration_ms,
                first_choice.get("finish_reason", "unknown"),
            )
            return str(content)

        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            self._record_failure(exc)
            logger.error("Local LLM connection error: %s", exc)
            raise ShieldBackendError(f"Local LLM backend connection failed: {exc}") from exc

        except httpx.TimeoutException as exc:
            self._record_failure(exc)
            logger.error("Local LLM inference timed out after %ds", self.config.request_timeout)
            raise ShieldBackendError(f"Local LLM backend timed out: {exc}") from exc

        except httpx.HTTPStatusError as exc:
            self._record_failure(exc)
            logger.error("Local LLM backend returned HTTP error status %d", exc.response.status_code)
            raise ShieldBackendError(f"Local LLM backend HTTP {exc.response.status_code}: {exc.response.text}") from exc

        except Exception as exc:
            if isinstance(exc, ShieldInferenceError):
                raise
            self._record_failure(exc)
            logger.error("Unexpected error during local LLM inference: %s", exc)
            raise ShieldBackendError(f"Unexpected local LLM backend error: {exc}") from exc
