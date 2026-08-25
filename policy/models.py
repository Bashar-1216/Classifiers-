"""
Policy decision models.

Defines the routing decision types used by the Policy Decision Layer (PRD §6.5).
The Policy Engine transforms a ClassificationResult into a PolicyDecision
that the Router can execute.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from classifier.models import ClassificationResult
from risk_engine.schemas import RiskDecision, TaskType


class Route(str, Enum):
    """Routing destination for a request."""

    NORMAL = "NORMAL"
    SHIELD = "SHIELD"
    CLOUD = "CLOUD"
    LOCAL_SHIELD = "LOCAL_SHIELD"
    LOCAL_PRIVATE = "LOCAL_PRIVATE"


class PolicyDecision(BaseModel):
    """
    Output of the Policy Decision Layer.

    Maps a classification result to a concrete routing decision.
    The Classifier only classifies — the Policy decides the route.
    """

    route: Route = Field(
        ...,
        description="Where to route this request: NORMAL/CLOUD or SHIELD/LOCAL_SHIELD",
    )
    reason: str = Field(
        ...,
        description="Human-readable explanation of the routing decision",
    )
    classification_result: Optional[ClassificationResult] = Field(
        default=None,
        description="The classification that led to this decision",
    )
    task_type: TaskType = Field(
        default=TaskType.CHAT,
        description="Task capability required (CHAT, EMBEDDING, RERANK)",
    )

    def to_risk_decision(self, metadata: Optional[Dict[str, Any]] = None) -> RiskDecision:
        """Convert PolicyDecision to unified RiskDecision schema."""
        cr = self.classification_result
        if cr:
            high_risk_cats = [k for k, v in cr.categories.items() if v >= 0.5]
            return RiskDecision(
                risk_score=cr.risk_score or cr.confidence,
                categories=high_risk_cats,
                category_scores=cr.categories,
                route=self.route,
                task_type=self.task_type,
                reasons=[self.reason] + cr.reasons,
                classification=cr.classification,
                confidence=cr.confidence,
                matched_rules=cr.matched_rules,
                metadata=metadata or {},
            )
        return RiskDecision(
            risk_score=0.0,
            categories=[],
            category_scores={},
            route=self.route,
            task_type=self.task_type,
            reasons=[self.reason],
            metadata=metadata or {},
        )
