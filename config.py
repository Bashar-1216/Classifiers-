"""
Configuration Settings for AI Risk Assessment & Governance System.

Loads settings from environment variables or .env file without any web framework coupling.
Supports Groq Cloud API, OpenAI, and Google Gemini out of the box.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """System configuration."""

    # --- Normal / Cloud Backend (Groq / OpenAI / Gemini) ---
    normal_backend_url: str = Field(
        default="https://api.groq.com/openai/v1",
        description="URL of the normal AI cloud backend (Groq OpenAI-compatible or Gemini API)",
        alias="NORMAL_BACKEND_URL",
    )
    normal_backend_api_key: str = Field(
        default="",
        description="API key for normal cloud backend (e.g. Groq API Key gsk_...)",
        alias="NORMAL_BACKEND_API_KEY",
    )
    normal_backend_model: str = Field(
        default="llama-3.3-70b-versatile",
        description="Model name for cloud inference (e.g. llama-3.3-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768)",
        alias="NORMAL_BACKEND_MODEL",
    )
    normal_backend_timeout: int = Field(
        default=60,
        description="Timeout in seconds for cloud backend requests",
        alias="NORMAL_BACKEND_TIMEOUT",
    )

    # --- Shield Service ---
    shield_service_url: str = Field(
        default="http://localhost:8001",
        description="URL of local isolated Shield environment",
        alias="SHIELD_SERVICE_URL",
    )
    shield_timeout: int = Field(
        default=120,
        description="Timeout in seconds for shield requests",
        alias="SHIELD_TIMEOUT",
    )

    # --- Rules & Knowledge ---
    rules_dir: str = Field(
        default="./rules",
        description="Path to YAML security rules",
        alias="RULES_DIR",
    )
    confidence_threshold: float = Field(
        default=0.5,
        description="Threshold for RESTRICTED classification",
        alias="CONFIDENCE_THRESHOLD",
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }
