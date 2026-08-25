"""
Classifier data models.

Defines the classification result types and rule matching models
used by the Classifier Service and Rule Engine.
"""

from __future__ import annotations

from enum import Enum

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


class ClassificationResult(BaseModel):
    """
    Complete Risk Assessment output from the AI Risk Assessment Layer.

    Produces unified risk scoring, multi-dimensional category breakdown,
    and granular detection reasons.
    """

    classification: Classification = Field(
        ...,
        description="Decision category: NORMAL or RESTRICTED",
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
        description="Multi-dimensional risk breakdown (e.g. security, privacy, business_confidential, context, metadata)",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="List of detected risk factors, triggers, or matched rules",
    )
    matched_rules: list[RuleMatch] = Field(
        default_factory=list,
        description="Detailed list of matched deterministic rules",
    )

