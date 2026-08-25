"""
Shield Service Configuration.

Defines environment-driven configuration settings for the Shield service using Pydantic Settings.
All settings can be overridden via environment variables prefixed with 'SHIELD_' or defined in .env.
"""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
