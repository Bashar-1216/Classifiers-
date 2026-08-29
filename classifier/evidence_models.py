"""
Core Evidence Contracts for Phase 1 — Evidence / Decision / Enforcement Separation.

Defines standardized, typed evidence payloads produced by security detectors.
Classifiers and detectors emit evidence ONLY. They have zero routing or policy authority.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScoreType(str, Enum):
    """Scientific nature of the emitted detector score."""

    SIMILARITY = "similarity"
    LOGIT = "logit"
    HEURISTIC = "heuristic"
    PROBABILITY = "probability"


class ConfidenceBand(str, Enum):
    """Categorical confidence rating derived during validation/calibration."""

    CLEAR_LOW = "CLEAR_LOW"
    GRAY = "GRAY"
    CLEAR_HIGH = "CLEAR_HIGH"


class DetectionSignal(BaseModel):
    """
    Standardized atomic finding emitted by an individual detection mechanism.
    Maintains strict scientific distinction between raw scores and calibrated probabilities.
    """

    detector_id: str = Field(..., description="Unique identifier of detector")
    detector_version: str = Field(default="1.0", description="Version of detector logic/weights")
    raw_score: float = Field(default=0.0, description="Raw uncalibrated score or similarity")
    score_type: ScoreType = Field(default=ScoreType.HEURISTIC, description="Scientific score type")
    calibrated_probability: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Calibrated probability (set ONLY after empirical calibration)",
    )
    calibration_version: Optional[str] = Field(
        default=None,
        description="Identifier of calibration curve/version used",
    )
    confidence_band: Optional[ConfidenceBand] = Field(
        default=None,
        description="Operational confidence band (CLEAR_LOW, GRAY, CLEAR_HIGH)",
    )
    applicable: bool = Field(default=True, description="Whether this detector was applicable to input")
    input_view: str = Field(default="raw", description="Input representation evaluated (raw/canonical/normalized)")
    latency_ms: float = Field(default=0.0, description="Execution duration in milliseconds")
    reason_codes: list[str] = Field(default_factory=list, description="Machine-readable trigger codes")


class PromptAttackEvidence(BaseModel):
    """Multi-label prompt attack evidence rail."""

    direct_injection: DetectionSignal = Field(default_factory=lambda: DetectionSignal(detector_id="prompt_attack.direct_injection"))
    jailbreak: DetectionSignal = Field(default_factory=lambda: DetectionSignal(detector_id="prompt_attack.jailbreak"))
    role_override: DetectionSignal = Field(default_factory=lambda: DetectionSignal(detector_id="prompt_attack.role_override"))
    system_prompt_extraction: DetectionSignal = Field(default_factory=lambda: DetectionSignal(detector_id="prompt_attack.system_prompt_extraction"))
    tool_schema_extraction: DetectionSignal = Field(default_factory=lambda: DetectionSignal(detector_id="prompt_attack.tool_schema_extraction"))
    indirect_injection: DetectionSignal = Field(default_factory=lambda: DetectionSignal(detector_id="prompt_attack.indirect_injection", applicable=False))
    obfuscation: DetectionSignal = Field(default_factory=lambda: DetectionSignal(detector_id="prompt_attack.obfuscation"))

    def get_max_score(self) -> float:
        """Helper to get highest raw score across attack dimensions."""
        return max(
            self.direct_injection.raw_score,
            self.jailbreak.raw_score,
            self.role_override.raw_score,
            self.system_prompt_extraction.raw_score,
            self.tool_schema_extraction.raw_score,
            self.obfuscation.raw_score,
        )


class ContentRiskEvidence(BaseModel):
    """Broad content safety and restricted cyber intent evidence rail."""

    unauthorized_cyber_intent: DetectionSignal = Field(default_factory=lambda: DetectionSignal(detector_id="content_risk.cyber_intent"))
    safety_hazards: dict[str, DetectionSignal] = Field(default_factory=dict, description="Category-specific safety signals")


class DlpEvidence(BaseModel):
    """Deterministic & pattern-based sensitive data detection rail."""

    has_credentials: bool = False
    has_pii: bool = False
    hard_invariant_violation: bool = False
    matched_secrets: list[str] = Field(default_factory=list)
    matched_pii_types: list[str] = Field(default_factory=list)
    signals: list[DetectionSignal] = Field(default_factory=list)


class ContextEvidence(BaseModel):
    """Multi-turn conversation trajectory and Salami assembly evidence."""

    multi_turn_depth: int = 0
    cumulative_assembly_detected: bool = False
    quoted_execution_trap: bool = False
    signals: list[DetectionSignal] = Field(default_factory=list)


class ScriptProfileEvidence(BaseModel):
    """
    Descriptive linguistic and script metadata extracted during canonicalization.
    IMPORTANT: Language/dialect/script metadata is observational context, NEVER an autonomous risk signal.
    """

    arabic_script: bool = False
    latin_script: bool = False
    mixed_script: bool = False
    arabizi_likelihood: float = 0.0
    detected_scripts: list[str] = Field(default_factory=list)
    obfuscation_types: list[str] = Field(default_factory=list)


class AuxiliaryEvidence(BaseModel):
    """
    Auxiliary signals used for triage, threat intelligence, and offline incident retrieval.
    IMPORTANT: BM25 and heuristics do not hold authoritative routing authority.
    """

    known_attack_similarity: float = 0.0
    matched_campaign_id: Optional[str] = None
    shannon_entropy: float = 0.0
    zero_width_count: int = 0
    signals: list[DetectionSignal] = Field(default_factory=list)


class JudgeEvidence(BaseModel):
    """
    Evidence emitted by the Local Judge during an ESCALATE cycle.
    The Judge produces evidence ONLY; it cannot make routing decisions.
    """

    judge_id: str = "local_judge"
    judge_version: str = "1.0"
    verdict: str = "UNCERTAIN"  # SAFE, UNSAFE, UNCERTAIN, ERROR
    confidence: float = 0.0
    hazard_categories: list[str] = Field(default_factory=list)
    adjudication_reason: str = ""
    sanitized_output: Optional[str] = None
    latency_ms: float = 0.0


class SecurityEvidence(BaseModel):
    """
    Standardized, multi-dimensional security evidence payload.
    Emitted by ClassifierService and passed to PolicyEngine for routing evaluation.
    Contains ZERO policy actions or routing destination decisions.
    """

    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    canonical_text: str = ""
    raw_prompt_hash: str = ""

    # Primary Security Rails
    prompt_attack: PromptAttackEvidence = Field(default_factory=PromptAttackEvidence)
    content_risk: ContentRiskEvidence = Field(default_factory=ContentRiskEvidence)
    dlp: DlpEvidence = Field(default_factory=DlpEvidence)
    context: ContextEvidence = Field(default_factory=ContextEvidence)

    # Context & Auxiliary Metadata
    script_profile: ScriptProfileEvidence = Field(default_factory=ScriptProfileEvidence)
    auxiliary: AuxiliaryEvidence = Field(default_factory=AuxiliaryEvidence)

    # Optional Escalation Evidence (Attached after Judge execution)
    judge_evidence: Optional[JudgeEvidence] = None

    # Telemetry
    total_latency_ms: float = 0.0
    detector_status: dict[str, str] = Field(default_factory=dict)
    all_reasons: list[str] = Field(default_factory=list)
    reasons_list: list[str] = Field(default_factory=list, alias="reasons")
    categories_dict: dict[str, float] = Field(default_factory=dict, alias="categories")
    matched_rules: list[Any] = Field(default_factory=list)
    classification: Any = None

    @property
    def risk_score(self) -> float:
        """Compatibility bridge for legacy callers."""
        return max(
            self.prompt_attack.get_max_score(),
            self.content_risk.unauthorized_cyber_intent.raw_score,
            1.0 if self.dlp.hard_invariant_violation else 0.0,
            max(self.categories_dict.values(), default=0.0),
        )

    @property
    def confidence(self) -> float:
        """Compatibility bridge for legacy confidence lookups."""
        return self.risk_score

    @property
    def reasons(self) -> list[str]:
        """Compatibility bridge for legacy reason list lookups."""
        return self.reasons_list or self.all_reasons

    @property
    def categories(self) -> dict[str, float]:
        """Compatibility bridge for legacy category score lookups."""
        if self.categories_dict:
            return self.categories_dict
        cats = {
            "security": self.prompt_attack.get_max_score(),
            "privacy": 1.0 if self.dlp.has_pii or self.dlp.has_credentials else 0.0,
            "cyber_intent": self.content_risk.unauthorized_cyber_intent.raw_score,
        }
        for k, v in self.content_risk.safety_hazards.items():
            cats[k] = v.raw_score
        return cats

