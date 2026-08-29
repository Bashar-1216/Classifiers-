"""
Phase 2.1 — Benchmark Hardening Schema & Scientific Metadata Contracts.

Defines:
1. Multi-Domain, Multi-Dialect, and Multi-Subtype Sample Definitions.
2. Two-Level Decoupled Metrics:
   - Level A: Standalone Detector Performance (PR-AUC, Recall, FPR, F1, Brier).
   - Level B: End-to-End System Performance (Cloud Admission FNR, Benign FPR, Escalation Rate).
3. Warm vs Cold Latency Rigor.
4. Cryptographic Dataset Provenance (Dataset SHA-256 Hash, Git Commit, Schema Version).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field

from policy.models import Route


class LanguageCode(str, Enum):
    """Linguistic and script categorization."""

    ARABIC = "ar"
    ENGLISH = "en"
    ARABIZI = "arabizi"
    CODE_SWITCH = "code_switch"
    OTHER = "other"


class DialectCode(str, Enum):
    """Fine-grained Arabic dialect classification."""

    MSA = "msa"
    EGYPTIAN = "egyptian"
    LEVANTINE = "levantine"
    GULF = "gulf"
    YEMENI = "yemeni"
    IRAQI = "iraqi"
    MAGHREBI = "maghrebi"
    SUDANESE = "sudanese"
    NONE = "none"


class DomainCode(str, Enum):
    """Broad application and semantic domain slices."""

    GENERAL = "general"
    EDUCATION = "education"
    MEDICINE_HEALTH = "medicine_health"
    FINANCE_BANKING = "finance_banking"
    TRAVEL_DAILY = "travel_daily"
    WORKPLACE = "workplace"
    CYBERSECURITY = "cybersecurity"
    PRIVACY_SECRETS = "privacy_secrets"
    FRAUD_SOCIAL_ENG = "fraud_social_eng"
    VIOLENCE_HARASSMENT = "violence_harassment"


class AttackFamily(str, Enum):
    """Taxonomy of attack types."""

    BENIGN = "benign"
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_EXPLOIT = "malware_exploit"
    SOCIAL_ENGINEERING = "social_engineering"
    PII_CREDENTIAL_LEAK = "pii_credential_leak"
    UNKNOWN = "unknown"


class AttackSubtype(str, Enum):
    """Granular attack mechanism taxonomy."""

    NONE = "none"
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_PLAY = "role_play"
    TOKEN_SMUGGLING = "token_smuggling"
    HYPOTHETICAL_FRAMING = "hypothetical_framing"
    ADVERSARIAL_SUFFIX = "adversarial_suffix"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    CONTEXT_LEAKAGE = "context_leakage"
    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_HARVESTING = "credential_harvesting"


class BenchmarkSample(BaseModel):
    """
    Immutable evaluation sample with stratified ground truth.
    """

    sample_id: str = Field(..., description="Unique sample identifier, e.g., GLF-ATT-001")
    text: str = Field(..., description="Exact raw prompt text to evaluate")
    language: LanguageCode = Field(default=LanguageCode.ARABIC)
    dialect: DialectCode = Field(default=DialectCode.NONE)
    domain: DomainCode = Field(default=DomainCode.GENERAL, description="Semantic domain slice")
    policy_label: Route = Field(..., description="Ground truth target policy route: NORMAL, RESTRICTED, BLOCK")
    attack_family: AttackFamily = Field(default=AttackFamily.BENIGN)
    attack_subtypes: list[str] = Field(default_factory=list, description="Specific attack mechanisms used")
    is_hard_negative: bool = Field(default=False, description="Benign sample with sensitive keywords/framing")
    is_obfuscated: bool = Field(default=False, description="Whether prompt utilizes encoding, spacing, or homoglyphs")
    human_verified: bool = Field(default=True, description="Whether labels were audited by human review")
    context_messages: list[dict[str, str]] = Field(default_factory=list, description="Optional conversation turns")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional provenance or notes")


class DetectorMetrics(BaseModel):
    """
    Level A: Intrinsic Standalone Detector Performance.
    Evaluates detector output directly before PolicyEngine/Router.
    """

    total_samples: int = 0
    positive_samples: int = 0
    negative_samples: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    fnr: float = 0.0  # Miss rate
    fpr: float = 0.0  # False alarm rate
    pr_auc: Optional[float] = None
    roc_auc: Optional[float] = None
    brier_score: Optional[float] = None


class SystemMetrics(BaseModel):
    """
    Level B: Extrinsic End-to-End Gateway Performance (Evidence + PDP + Escalation).
    """

    cloud_admission_fnr: float = 0.0  # Critical Security SLA: % of Restricted traffic leaked to Cloud
    benign_overblock_fpr: float = 0.0  # UX metric: % of Benign traffic blocked or sent to Shield
    block_accuracy: float = 0.0
    escalation_rate: float = 0.0
    route_distribution: dict[str, int] = Field(default_factory=dict)


class BenchmarkLatencyMetrics(BaseModel):
    """Execution latency percentiles separating cold start from steady-state."""

    cold_start_ms: float = 0.0
    warmup_count: int = 0
    warm_p50_ms: float = 0.0
    warm_p95_ms: float = 0.0
    warm_p99_ms: float = 0.0
    warm_mean_ms: float = 0.0
    steady_state_throughput: float = 0.0


class SliceMetrics(BaseModel):
    """Performance slice for a specific dialect, domain, or test category."""

    slice_name: str
    total: int = 0
    restricted_actual: int = 0
    restricted_missed_fn: int = 0
    fnr: float = 0.0
    benign_actual: int = 0
    benign_false_alarms_fp: int = 0
    fpr: float = 0.0
    detector_recall: float = 0.0
    detector_precision: float = 0.0


class BenchmarkProvenance(BaseModel):
    """Immutable experiment metadata tracking exact environment, dataset hash, and code state."""

    git_commit: str = "unknown"
    dataset_name: str = "dialects_gold_v1"
    dataset_version: str = "1.0.0"
    dataset_hash_sha256: str = ""
    policy_version: str = "1.1.0"
    classifier_version: str = "c0-frozen"
    run_timestamp: str = ""
    hardware_device: str = "CPU"


class BenchmarkMetrics(BaseModel):
    """Complete aggregated benchmark report object."""

    provenance: BenchmarkProvenance = Field(default_factory=BenchmarkProvenance)
    detector_metrics: DetectorMetrics = Field(default_factory=DetectorMetrics)
    system_metrics: SystemMetrics = Field(default_factory=SystemMetrics)
    latency: BenchmarkLatencyMetrics = Field(default_factory=BenchmarkLatencyMetrics)
    per_dialect: dict[str, SliceMetrics] = Field(default_factory=dict)
    per_domain: dict[str, SliceMetrics] = Field(default_factory=dict)
    hard_negatives: SliceMetrics = Field(default_factory=lambda: SliceMetrics(slice_name="hard_negatives"))
    obfuscation: SliceMetrics = Field(default_factory=lambda: SliceMetrics(slice_name="obfuscation"))
