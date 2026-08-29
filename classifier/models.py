"""
Classifier data models and Evidence re-exports.

Maintains backward compatibility while enforcing Phase 1 Evidence contracts.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from classifier.evidence_models import (
    ConfidenceBand,
    ScoreType,
    DetectionSignal,
    PromptAttackEvidence,
    ContentRiskEvidence,
    DlpEvidence,
    ContextEvidence,
    ScriptProfileEvidence,
    AuxiliaryEvidence,
    JudgeEvidence,
    SecurityEvidence,
)


class Classification(str, Enum):
    """Legacy classification compatibility enum."""

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
    """Legacy normalized finding from an individual detector."""

    detector: str = Field(..., description="Name of the detector")
    categories: list[str] = Field(default_factory=list, description="Target threat categories")
    score: float = Field(..., ge=0.0, le=1.0, description="Risk intensity score")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in finding")
    status: str = Field(default="triggered", description="Status e.g. triggered, passed, errored")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Raw supporting evidence")
    version: str = Field(default="1.0", description="Detector engine version")


# Standard Phase 1 Aliases
RiskEvidence = SecurityEvidence
ClassificationResult = SecurityEvidence

__all__ = [
    "Classification",
    "Severity",
    "RuleType",
    "RuleDefinition",
    "RuleMatch",
    "DetectionResult",
    "ScoreType",
    "ConfidenceBand",
    "DetectionSignal",
    "PromptAttackEvidence",
    "ContentRiskEvidence",
    "DlpEvidence",
    "ContextEvidence",
    "ScriptProfileEvidence",
    "AuxiliaryEvidence",
    "JudgeEvidence",
    "SecurityEvidence",
    "RiskEvidence",
    "ClassificationResult",
]
