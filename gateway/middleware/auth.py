"""
Authentication middleware — API Key validation.

Validates the Authorization header against configured API keys
using constant-time comparison to prevent timing attacks. (PRD §6.1)
"""

from __future__ import annotations

import logging
import secrets

from fastapi import Request, HTTPException, status

logger = logging.getLogger(__name__)

# Paths that don't require authentication
PUBLIC_PATHS = {"/health", "/health/ready", "/docs", "/redoc", "/openapi.json"}


class AuthMiddleware:
    """
    API Key authentication middleware.

    Validates Bearer tokens in the Authorization header against
    a configured list of valid API keys.
    """

    def __init__(self, valid_api_keys: list[str]) -> None:
        self.valid_api_keys = valid_api_keys

    async def verify(self, request: Request) -> str:
        """
        Verify the API key from the request.

        Args:
            request: The incoming FastAPI request.

        Returns:
            The validated API key.

        Raises:
            HTTPException: 401 if the key is missing or invalid.
        """
        # Skip auth for public endpoints
        if request.url.path in PUBLIC_PATHS:
            return "public"

        auth_header = request.headers.get("Authorization")

        if not auth_header:
            logger.warning("Missing Authorization header from %s", request.client.host if request.client else "unknown")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header. Use: Authorization: Bearer <api-key>",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Parse "Bearer <key>"
        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization format. Use: Authorization: Bearer <api-key>",
                headers={"WWW-Authenticate": "Bearer"},
            )

        provided_key = parts[1].strip()

        # Constant-time comparison against all valid keys
        if not self._validate_key(provided_key):
            logger.warning("Invalid API key attempt from %s", request.client.host if request.client else "unknown")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return provided_key

    def _validate_key(self, provided_key: str) -> bool:
        """
        Validate the provided key against all valid keys.

        Uses secrets.compare_digest for constant-time comparison
        to prevent timing attacks.
        """
        for valid_key in self.valid_api_keys:
            if secrets.compare_digest(provided_key, valid_key):
                return True
        return False
