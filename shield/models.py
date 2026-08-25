"""
Shield Service Data Models.

Defines Pydantic v2 schemas and enumerations for the Shield service,
including request/response models, judge verdicts, and circuit breaker states.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class JudgeVerdict(str, Enum):
    """
    Verdict produced by the Local Judge evaluation.

    - ALLOW: Request or response is safe to proceed unmodified.
    - DENY: Request or response contains critical security violations; rejected.
    - REDACT: Response contains sensitive PII (e.g., SSN, credit cards) and must be sanitized.
    """

    ALLOW = "ALLOW"
    DENY = "DENY"
    REDACT = "REDACT"


class CircuitState(str, Enum):
    """
    Operational state of the circuit breaker protecting local LLM inference.

    - CLOSED: Normal operation; requests are forwarded to local backend.
    - OPEN: Backend is failing; requests are rejected immediately without calling backend.
    - HALF_OPEN: Cooldown period elapsed; a probe request is permitted to test recovery.
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ShieldRequest(BaseModel):
    """
    Input schema for the Shield service processing endpoint (/v1/shield/process).

    Contains the conversation messages and optional classifier/gateway metadata.
    """

    messages: list[dict[str, Any]] = Field(
        ...,
        min_length=1,
        description="List of conversation message dictionaries, each containing 'role' and 'content'",
        examples=[[{"role": "user", "content": "Explain quantum computing."}]],
    )
    metadata: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional request metadata (e.g., user_id, session_id)",
    )
    classification_result: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional classification details produced by the gateway classifier",
    )


class ShieldResponse(BaseModel):
    """
    Output schema returned by the Shield service after local inference and safety evaluation.
    """

    response: str = Field(
        ...,
        description="The processed (and potentially redacted) model response text",
    )
    judge_verdict: JudgeVerdict = Field(
        ...,
        description="Verdict assigned to the response by the Local Judge",
    )
    processing_time_ms: float = Field(
        ...,
        ge=0.0,
        description="Total elapsed processing time in milliseconds",
    )
    model_used: Optional[str] = Field(
        default=None,
        description="Identifier of the local model used for inference",
    )
    request_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique request tracking identifier",
    )


class ShieldHealthResponse(BaseModel):
    """
    Health check response model for the Shield service (/health).
    """

    status: str = Field(
        ...,
        description="Current health status of the Shield service ('healthy', 'degraded', or 'unhealthy')",
    )
    circuit_state: CircuitState = Field(
        ...,
        description="Current operational state of the circuit breaker",
    )
    service: str = Field(
        default="shield",
        description="Service identifier",
    )
