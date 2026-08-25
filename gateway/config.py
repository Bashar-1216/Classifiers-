"""
Gateway configuration — Environment-based settings.

All configuration is loaded from environment variables or .env file
using pydantic-settings. No secrets in code.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Gateway configuration loaded from environment variables."""

    # --- Authentication ---
    api_keys: str = Field(
        default="sk-test-key-1,sk-test-key-2",
        description="Comma-separated list of valid API keys",
        alias="GATEWAY_API_KEYS",
    )

    # --- Rate Limiting ---
    rate_limit_per_minute: int = Field(
        default=60,
        description="Maximum requests per minute per API key",
        alias="RATE_LIMIT_PER_MINUTE",
    )

    # --- Normal Backend ---
    normal_backend_url: str = Field(
        default="https://api.openai.com",
        description="URL of the normal AI backend",
        alias="NORMAL_BACKEND_URL",
    )
    normal_backend_api_key: str = Field(
        default="",
        description="API key for the normal backend",
        alias="NORMAL_BACKEND_API_KEY",
    )
    normal_backend_model: str = Field(
        default="gemini-1.5-flash",
        description="Default model name for the normal backend",
        alias="NORMAL_BACKEND_MODEL",
    )
    normal_backend_timeout: int = Field(
        default=60,
        description="Timeout in seconds for normal backend requests",
        alias="NORMAL_BACKEND_TIMEOUT",
    )

    # --- Shield Service ---
    shield_service_url: str = Field(
        default="http://localhost:8001",
        description="URL of the Shield service",
        alias="SHIELD_SERVICE_URL",
    )
    shield_timeout: int = Field(
        default=120,
        description="Timeout in seconds for shield requests",
        alias="SHIELD_TIMEOUT",
    )

    # --- Rules ---
    rules_dir: str = Field(
        default="./rules",
        description="Path to the rules directory",
        alias="RULES_DIR",
    )

    # --- Classification ---
    confidence_threshold: float = Field(
        default=0.5,
        description="Confidence threshold for RESTRICTED classification",
        alias="CONFIDENCE_THRESHOLD",
    )

    # --- Server ---
    host: str = Field(default="0.0.0.0", alias="GATEWAY_HOST")
    port: int = Field(default=8000, alias="GATEWAY_PORT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @property
    def api_keys_list(self) -> list[str]:
        """Parse comma-separated API keys into a list."""
        return [key.strip() for key in self.api_keys.split(",") if key.strip()]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }
