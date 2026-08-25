"""
Unified Schemas for AI Risk Engine, Policy Engine, and Gateway.

Defines the core data contracts across all pipeline stages:
- RiskDecision: Unified decision object consumed by Router & Observability
- Route: Target destination (CLOUD / LOCAL_SHIELD / LOCAL_PRIVATE)
- TaskType: Processing capability (CHAT / EMBEDDING / RERANK)
- Core classification & rule models
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from classifier.models import Classification, RuleMatch, RuleType, Severity


class Route(str, Enum):
    """Routing destinations for request dispatching."""

    CLOUD = "CLOUD"
    LOCAL_SHIELD = "LOCAL_SHIELD"
    LOCAL_PRIVATE = "LOCAL_PRIVATE"
    # Legacy aliases for backward compatibility with existing tests/routes
    NORMAL = "NORMAL"
    SHIELD = "SHIELD"

    @classmethod
    def normalize(cls, val: str | Route) -> Route:
        """Normalize legacy route names to standard routes."""
        s = str(val).upper()
        if s in ("NORMAL", "CLOUD"):
            return cls.CLOUD
        if s in ("SHIELD", "LOCAL_SHIELD"):
            return cls.LOCAL_SHIELD
        if s in ("LOCAL_PRIVATE", "PRIVATE"):
            return cls.LOCAL_PRIVATE
        return cls(val)


class TaskType(str, Enum):
    """Processing capability / workload type."""

    CHAT = "CHAT"
    EMBEDDING = "EMBEDDING"
    RERANK = "RERANK"


class RiskDecision(BaseModel):
    """
    Unified Decision Object.

    Standardized contract emitted after Risk Assessment and Policy evaluation.
    Consumed by Router, Output Safety, and Observability layers.
    """

    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Unified aggregated risk score (0.0 to 1.0)",
    )
    categories: List[str] = Field(
        default_factory=list,
        description="List of detected high-risk categories (e.g. ['PII', 'JAILBREAK'])",
    )
    category_scores: Dict[str, float] = Field(
        default_factory=dict,
        description="Fine-grained category breakdown with numeric scores",
    )
    route: Route = Field(
        default=Route.CLOUD,
        description="Target destination route (CLOUD, LOCAL_SHIELD, LOCAL_PRIVATE)",
    )
    task_type: TaskType = Field(
        default=TaskType.CHAT,
        description="Workload processing type (CHAT, EMBEDDING, RERANK)",
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable explanations and detection triggers",
    )
    classification: Classification = Field(
        default=Classification.NORMAL,
        description="High-level classification (NORMAL or RESTRICTED)",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score in the decision",
    )
    matched_rules: List[RuleMatch] = Field(
        default_factory=list,
        description="List of deterministic rules matched",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Caller metadata and environmental context",
    )
