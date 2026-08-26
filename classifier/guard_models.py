"""
Typed Evidence Contracts for Neural Guard Subsystem.
Strictly decoupled from Policy Engine and Routing Decisions.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GuardVerdict(str, Enum):
    SAFE = "SAFE"
    UNSAFE = "UNSAFE"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class GuardMode(str, Enum):
    DISABLED = "DISABLED"
    SHADOW = "SHADOW"
    ENFORCE = "ENFORCE"


class GuardEvidence(BaseModel):
    """
    Standardized typed safety evidence produced by the Neural Guard model.
    Contains zero routing decisions — strictly factual safety measurements.
    """
    verdict: GuardVerdict = Field(default=GuardVerdict.SAFE, description="Raw safety verdict")
    raw_output: str = Field(default="", description="Exact decoded string from model")
    raw_categories: List[str] = Field(default_factory=list, description="Extracted category codes (e.g. S1, S2)")
    canonical_categories: List[str] = Field(default_factory=list, description="Mapped canonical taxonomy tags")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score")
    latency_ms: float = Field(default=0.0, description="Inference latency in milliseconds")
    model_id: str = Field(default="unknown", description="Identifier of the executing model")
    model_revision: str = Field(default="unknown", description="Revision/hash of model weights")
    status: str = Field(default="ok", description="Execution status: ok, timeout, fallback, error")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional telemetry")

    @property
    def is_unsafe(self) -> bool:
        return self.verdict == GuardVerdict.UNSAFE

    @property
    def is_available(self) -> bool:
        return self.verdict in (GuardVerdict.SAFE, GuardVerdict.UNSAFE)
