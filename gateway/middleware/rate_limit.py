"""
Rate Limiting middleware — In-memory sliding window.

Tracks request timestamps per API key and enforces a configurable
requests-per-minute limit. (PRD §6.1)
Emits structured audit failure events when rate limits are exceeded.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from gateway.observability import AuditLogger

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    In-memory sliding window rate limiter.

    Tracks request timestamps per API key using a deque.
    Old entries are automatically cleaned up on each check.
    """

    def __init__(self, requests_per_minute: int = 60) -> None:
        self.requests_per_minute = requests_per_minute
        self.window_seconds = 60.0
        # key → deque of timestamps
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    async def check(self, request: Request, api_key: str) -> None:
        """
        Check if the request is within rate limits.

        Args:
            request: The incoming FastAPI request.
            api_key: The authenticated API key to track.

        Raises:
            HTTPException: 429 if rate limit exceeded.
        """
        if api_key == "public":
            return  # Don't rate-limit health checks or public endpoints

        now = time.monotonic()
        window_start = now - self.window_seconds

        # Get the request deque for this API key
        req_times = self._requests[api_key]

        # Clean up old entries outside the window
        while req_times and req_times[0] < window_start:
            req_times.popleft()

        # Check if limit is exceeded
        if len(req_times) >= self.requests_per_minute:
            # Calculate retry-after from oldest request in window
            oldest = req_times[0]
            retry_after = int(oldest - window_start) + 1

            request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex
            AuditLogger.log_failure(
                request_id=request_id,
                event_type="RATE_LIMIT_EXCEEDED",
                status_code=429,
                detail=f"Rate limit of {self.requests_per_minute} req/min exceeded",
            )

            logger.warning(
                "Rate limit exceeded for key=%s...%s (%d/%d in window)",
                api_key[:8],
                api_key[-4:] if len(api_key) > 8 else "",
                len(req_times),
                self.requests_per_minute,
            )

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {self.requests_per_minute} requests per minute.",
                headers={"Retry-After": str(max(1, retry_after))},
            )

        # Record this request
        req_times.append(now)

    def get_usage(self, api_key: str) -> dict[str, int]:
        """Get current usage stats for an API key."""
        now = time.monotonic()
        window_start = now - self.window_seconds
        req_times = self._requests.get(api_key, deque())

        # Count only requests within current window
        current = sum(1 for t in req_times if t >= window_start)

        return {
            "current": current,
            "limit": self.requests_per_minute,
            "remaining": max(0, self.requests_per_minute - current),
        }
