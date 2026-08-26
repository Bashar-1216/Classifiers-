"""
Shield Service Configuration.

Defines environment-driven configuration settings for the Shield service using Pydantic Settings.
All settings can be overridden via environment variables prefixed with 'SHIELD_' or defined in .env.
Enforces Application-Level Air-Gap validation when shield_mode is 'local_isolated'.
"""

from __future__ import annotations

import ipaddress
import urllib.parse

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ALLOWED_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "local_llm", "shield_fast"}


class ShieldConfig(BaseSettings):
    """
    Configuration settings for the Shield service.

    Shield runs in an isolated network environment with local LLM access only.
    """

    model_config = SettingsConfigDict(
        env_prefix="SHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    shield_mode: str = Field(
        default="local_isolated",
        validation_alias=AliasChoices("SHIELD_MODE", "shield_mode"),
        description="Shield mode: 'local_isolated' (strictly local/private network) or 'cloud_poc'",
    )
    local_llm_url: str = Field(
        default="http://localhost:8100/v1",
        validation_alias=AliasChoices("SHIELD_LOCAL_LLM_URL", "LOCAL_LLM_URL", "local_llm_url"),
        description="URL of the OpenAI-compatible local LLM server",
    )
    local_llm_model: str = Field(
        default="meta-llama/Meta-Llama-3-8B-Instruct",
        validation_alias=AliasChoices("SHIELD_LOCAL_LLM_MODEL", "LOCAL_LLM_MODEL", "local_llm_model"),
        description="Local LLM model identifier for inference",
    )
    request_timeout: int = Field(
        default=120,
        gt=0,
        validation_alias=AliasChoices("SHIELD_REQUEST_TIMEOUT", "REQUEST_TIMEOUT", "request_timeout"),
        description="Request timeout in seconds for local LLM inference",
    )
    max_request_size: int = Field(
        default=10000,
        gt=0,
        validation_alias=AliasChoices("SHIELD_MAX_REQUEST_SIZE", "MAX_REQUEST_SIZE", "max_request_size"),
        description="Maximum allowed total character length for incoming messages",
    )
    circuit_breaker_threshold: int = Field(
        default=3,
        gt=0,
        validation_alias=AliasChoices("SHIELD_CIRCUIT_BREAKER_THRESHOLD", "CIRCUIT_BREAKER_THRESHOLD", "circuit_breaker_threshold"),
        description="Number of consecutive failures before opening circuit breaker",
    )
    circuit_breaker_recovery: int = Field(
        default=30,
        gt=0,
        validation_alias=AliasChoices("SHIELD_CIRCUIT_BREAKER_RECOVERY", "CIRCUIT_BREAKER_RECOVERY", "circuit_breaker_recovery"),
        description="Cooldown duration in seconds before testing circuit recovery (HALF_OPEN)",
    )
    host: str = Field(
        default="0.0.0.0",
        validation_alias=AliasChoices("SHIELD_HOST", "HOST", "host"),
        description="Host interface to bind the Shield service to",
    )
    port: int = Field(
        default=8001,
        gt=0,
        le=65535,
        validation_alias=AliasChoices("SHIELD_PORT", "PORT", "port"),
        description="Port number to run the Shield service on",
    )
    log_level: str = Field(
        default="INFO",
        validation_alias=AliasChoices("SHIELD_LOG_LEVEL", "LOG_LEVEL", "log_level"),
        description="Logging level for the Shield service (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )

    @classmethod
    def validate_isolation_url(cls, url: str) -> None:
        """Validate that URL is restricted to loopback or private network."""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Air-Gap Guard: Invalid scheme '{parsed.scheme}'. Must be http or https.")

        hostname = parsed.hostname or ""
        if not hostname:
            raise ValueError(f"Air-Gap Guard: No hostname found in URL: {url}")

        if hostname.lower() in ALLOWED_LOCAL_HOSTNAMES:
            return

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback or ip.is_private:
                return
            raise ValueError(
                f"Air-Gap Guard: Public IP address '{hostname}' is forbidden in isolated mode. "
                "Local inference must use loopback or private network."
            )
        except ValueError as err:
            if "forbidden in isolated mode" in str(err):
                raise
            raise ValueError(
                f"Air-Gap Guard: Hostname '{hostname}' is not a permitted local backend. "
                "Cloud hostnames (e.g. googleapis.com, openai.com) are strictly forbidden in isolated mode."
            )
