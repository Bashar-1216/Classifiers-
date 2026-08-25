"""
Gateway request/response schemas.

These Pydantic v2 models define the API contract for the Secure AI Gateway.
All requests and responses flow through these schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class Message(BaseModel):
    """A single chat message in the conversation."""

    role: str = Field(
        ...,
        description="Role of the message sender: 'system', 'user', or 'assistant'",
        examples=["user", "assistant", "system"],
    )
    content: str = Field(
        ...,
        description="The text content of the message",
        examples=["Hello, how are you?"],
    )


class RequestMetadata(BaseModel):
    """Enterprise metadata attached to a chat request for risk assessment."""

    user_id: Optional[str] = Field(
        default=None,
        description="Unique identifier of the requesting user",
    )
    user_role: Optional[str] = Field(
        default="employee",
        description="User role or privilege tier (e.g. 'guest', 'contractor', 'employee', 'admin')",
    )
    department: Optional[str] = Field(
        default=None,
        description="Department or team (e.g. 'finance', 'engineering', 'legal', 'executive')",
    )
    project_sensitivity: Optional[str] = Field(
        default="internal",
        description="Data sensitivity classification (e.g. 'public', 'internal', 'confidential', 'strictly_confidential')",
    )
    environment: Optional[str] = Field(
        default="production",
        description="Network/app environment (e.g. 'public_internet', 'internal_vpn', 'secure_enclave')",
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Session identifier for multi-turn conversation tracking",
    )


class ChatRequest(BaseModel):
    """
    Main input schema for the /v1/chat/completions endpoint.

    Accepts either a direct prompt or a list of messages (or both).
    Compatible with OpenAI chat completions format.
    """

    prompt: Optional[str] = Field(
        default=None,
        description="Direct user prompt (alternative to messages)",
    )
    messages: list[Message] = Field(
        default_factory=list,
        description="List of conversation messages",
    )
    metadata: Optional[RequestMetadata] = Field(
        default=None,
        description="Optional request metadata",
    )
    model: Optional[str] = Field(
        default=None,
        description="Model to use for inference (configurable)",
    )
    temperature: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=2.0,
        description="Sampling temperature",
    )
    max_tokens: Optional[int] = Field(
        default=None,
        gt=0,
        description="Maximum tokens to generate",
    )
    stream: bool = Field(
        default=False,
        description="Whether to stream the response",
    )

    def get_full_text(self) -> str:
        """
        Extract all user-facing text from the request for classification.

        Combines the prompt and all message contents into a single string
        for the classifier to analyze.
        """
        parts: list[str] = []
        if self.prompt:
            parts.append(self.prompt)
        for msg in self.messages:
            parts.append(msg.content)
        return " ".join(parts)


class ChatResponse(BaseModel):
    """
    Main output schema returned by the Gateway.

    Includes the AI response along with routing metadata for transparency.
    """

    id: str = Field(
        default_factory=lambda: f"chatcmpl-{uuid.uuid4().hex[:12]}",
        description="Unique response identifier",
    )
    object: str = Field(
        default="chat.completion",
        description="Object type",
    )
    created: int = Field(
        default_factory=lambda: int(datetime.now(timezone.utc).timestamp()),
        description="Unix timestamp of response creation",
    )
    model: Optional[str] = Field(
        default=None,
        description="Model used for inference",
    )
    choices: list[ChatChoice] = Field(
        default_factory=list,
        description="List of completion choices",
    )
    route_taken: Optional[str] = Field(
        default=None,
        description="Which route was used: 'NORMAL' or 'SHIELD'",
    )
    request_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique request tracking ID",
    )


class ChatChoice(BaseModel):
    """A single completion choice."""

    index: int = Field(default=0, description="Choice index")
    message: Message = Field(..., description="The generated message")
    finish_reason: Optional[str] = Field(
        default="stop",
        description="Reason the generation stopped",
    )


class ErrorResponse(BaseModel):
    """Standard error response format."""

    error: str = Field(..., description="Error type or category")
    code: str = Field(..., description="Machine-readable error code")
    detail: str = Field(..., description="Human-readable error description")
    request_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Request tracking ID for debugging",
    )


# Rebuild ChatResponse to resolve forward reference to ChatChoice
ChatResponse.model_rebuild()
