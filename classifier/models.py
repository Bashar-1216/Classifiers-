"""
Classifier data models.

Defines the classification result types, rule matching models,
and structured RiskEvidence contracts used across the gateway.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Classification(str, Enum):
    """Request classification result."""

    NORMAL = "NORMAL"
    RESTRICTED = "RESTRICTED"


class Severity(str, Enum):
    """Rule severity levels with associated confidence scores."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def score(self) -> float:
        """Numeric confidence score for this severity level."""
        return {
            Severity.LOW: 0.3,
            Severity.MEDIUM: 0.6,
            Severity.HIGH: 0.9,
        }[self]


class RuleType(str, Enum):
    """Type of pattern matching used by a rule."""

    KEYWORD = "keyword"
    REGEX = "regex"


class RuleDefinition(BaseModel):
    """A single security rule loaded from YAML configuration."""

    name: str = Field(..., description="Unique rule identifier")
    type: RuleType = Field(..., description="Pattern matching type")
    severity: Severity = Field(..., description="Rule severity level")
    patterns: list[str] = Field(..., description="List of patterns to match")
    description: str | None = Field(
        default=None,
        description="Human-readable description of what this rule detects",
    )
    enabled: bool = Field(default=True, description="Whether the rule is active")


class RuleMatch(BaseModel):
    """Result of a single rule matching against input text."""

    rule_name: str = Field(..., description="Name of the matched rule")
    pattern_matched: str = Field(..., description="The specific pattern that matched")
    severity: Severity = Field(..., description="Severity of the matched rule")
    match_type: RuleType = Field(..., description="How the match was found")


class DetectionResult(BaseModel):
    """Normalized finding from an individual detector."""

    detector: str = Field(..., description="Name of the detector")
    categories: list[str] = Field(default_factory=list, description="Target threat categories")
    score: float = Field(..., ge=0.0, le=1.0, description="Risk intensity score")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in finding")
    status: str = Field(default="triggered", description="Status e.g. triggered, passed, errored")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Raw supporting evidence")
    version: str = Field(default="1.0", description="Detector engine version")


class RiskEvidence(BaseModel):
    """
    Standardized, multi-dimensional risk evidence payload.
    Passed directly to the Policy Engine for routing decisions.
    """

    classification: Classification = Field(
        ...,
        description="Preliminary classification category: NORMAL or RESTRICTED",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Overall risk confidence score (0.0 to 1.0)",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Aggregated risk score across all threat dimensions",
    )
    categories: dict[str, float] = Field(
        default_factory=dict,
        description="Multi-dimensional risk breakdown",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="List of detected risk factors, triggers, or matched rules",
    )
    matched_rules: list[RuleMatch] = Field(
        default_factory=list,
        description="Detailed list of matched deterministic rules",
    )
    detections: list[DetectionResult] = Field(
        default_factory=list,
        description="Granular findings from all active detectors",
    )
    correlations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Abstract multi-axis threat correlations",
    )
    uncertainty: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Estimated uncertainty in classification",
    )
    detector_status: dict[str, str] = Field(
        default_factory=dict,
        description="Operational health status of detectors",
    )


# Alias for backwards compatibility
ClassificationResult = RiskEvidence
