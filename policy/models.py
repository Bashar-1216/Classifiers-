"""
Policy decision models.

Defines the routing decision types used by the Policy Decision Layer (PRD §6.5).
The Policy Engine transforms a ClassificationResult into a PolicyDecision
that the Router can execute.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from classifier.models import ClassificationResult


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
    classification_result: ClassificationResult | None = Field(
        default=None,
        description="The classification that led to this decision",
    )
