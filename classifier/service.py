"""
AI Risk Assessment Layer — Main Orchestrator (ClassifierService).

Evidence Producer ONLY (Phase 1 — Evidence / Decision / Enforcement Separation).
Emits standardized SecurityEvidence without any routing authority or decision strings.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, List, Optional

from classifier.context_analyzer import ContextAnalyzer
from classifier.defenseclaw_metrics import DefenseClawMetrics
from classifier.evidence_models import (
    AuxiliaryEvidence,
    ConfidenceBand,
    ContentRiskEvidence,
    ContextEvidence,
    DetectionSignal,
    DlpEvidence,
    PromptAttackEvidence,
    ScoreType,
    ScriptProfileEvidence,
    SecurityEvidence,
)
from classifier.lexical_engine import LexicalSignalEngine
from classifier.metadata_analyzer import MetadataAnalyzer
from classifier.models import Classification, DetectionResult, RuleMatch
from classifier.normalizer import TextNormalizer
from classifier.risk_aggregator import RiskAggregator
from classifier.risk_correlator import RiskAxesCorrelator
from classifier.rule_engine import RuleEngine
from classifier.semantic_classifier import SemanticClassifier
from classifier.structure_engine import StructureSignalEngine
from risk_engine.specialized import JailbreakDetector, PIIDetector, SafetyDetector
from risk_engine.specialized.dlp_validator import DLPValidator

logger = logging.getLogger(__name__)


class ClassifierService:
    """
    Evidence Producer Service.
    Executes multi-rail signal extraction and emits standardized SecurityEvidence.
    Holds ZERO routing decision authority.
    """

    def __init__(
        self,
        rules_dir: str | None = None,
        confidence_threshold: float = 0.50,
        guard_model_path: str | None = None,
    ) -> None:
        self.rule_engine = RuleEngine(rules_dir)
        self.lexical_engine = LexicalSignalEngine()
        self.structure_engine = StructureSignalEngine()
        self.defenseclaw_metrics = DefenseClawMetrics()

        self.semantic_classifier = SemanticClassifier(guard_model_path=guard_model_path)
        self.pii_detector = PIIDetector()
        self.jailbreak_detector = JailbreakDetector()
        self.safety_detector = SafetyDetector()
        self.dlp_validator = DLPValidator()

        self.context_analyzer = ContextAnalyzer()
        self.metadata_analyzer = MetadataAnalyzer()
        self.risk_correlator = RiskAxesCorrelator()
        self.risk_aggregator = RiskAggregator(confidence_threshold=confidence_threshold)
        self.confidence_threshold = confidence_threshold

        logger.info(
            "ClassifierService initialized as Evidence Producer (Rules: %d).",
            len(self.rule_engine.rules),
        )

    def classify(
        self,
        text: str,
        messages: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SecurityEvidence:
        """
        Execute risk assessment pipeline and produce structured SecurityEvidence.
        """
        start_time = time.perf_counter()
        if not text or not text.strip():
            return SecurityEvidence(
                canonical_text="",
                raw_prompt_hash="",
                detector_status={"gateway": "idle"},
                classification=Classification.NORMAL,
            )

        try:
            prompt_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
            detections: list[DetectionResult] = []
            detector_status: dict[str, str] = {}
            all_reasons: list[str] = []

            # 1. Canonicalization & Script Profile
            script_meta = TextNormalizer.extract_script_profile(text)
            script_profile = ScriptProfileEvidence(
                arabic_script=script_meta["arabic_script"],
                latin_script=script_meta["latin_script"],
                mixed_script=script_meta["mixed_script"],
                arabizi_likelihood=script_meta["arabizi_likelihood"],
                detected_scripts=script_meta["detected_scripts"],
                obfuscation_types=script_meta["obfuscation_types"],
            )
            variants = TextNormalizer.get_all_normalized_variants(text)
            canonical_text = variants[0][0] if variants else text

            # 2. Deterministic Invariants & Rules
            rule_matches: list[RuleMatch] = []
            matched_rule_names = set()
            max_rule_score = 0.0

            for variant_text, source_tag in variants:
                matches = self.rule_engine.evaluate(variant_text)
                for m in matches:
                    if m.rule_name not in matched_rule_names:
                        matched_rule_names.add(m.rule_name)
                        max_rule_score = max(max_rule_score, m.severity.score)
                        tag = f" [{source_tag}]" if source_tag != "direct_text" else ""
                        rule_matches.append(
                            RuleMatch(
                                rule_name=f"{m.rule_name}{tag}",
                                pattern_matched=m.pattern_matched,
                                severity=m.severity,
                                match_type=m.match_type,
                            )
                        )
                        all_reasons.append(f"rule:{m.rule_name}")
            detector_status["rule_engine"] = "active"

            # 3. Prompt Attack Rail (Semantic & Specialized Detectors)
            semantic_scores: dict[str, float] = {}
            max_semantic_score = 0.0
            for variant_text, source_tag in variants:
                v_scores = self.semantic_classifier.evaluate(variant_text)
                for cat, score in v_scores.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    semantic_scores[tag_name] = max(semantic_scores.get(tag_name, 0.0), score)
                    max_semantic_score = max(max_semantic_score, score)

            jailbreak_findings: dict[str, float] = {}
            for variant_text, source_tag in variants:
                jb_res = self.jailbreak_detector.evaluate(variant_text)
                jailbreak_findings.update(jb_res)

            prompt_attack = PromptAttackEvidence(
                direct_injection=DetectionSignal(
                    detector_id="semantic_guard.direct_injection",
                    raw_score=round(max_semantic_score, 4),
                    score_type=ScoreType.SIMILARITY,
                    confidence_band=ConfidenceBand.CLEAR_HIGH if max_semantic_score >= 0.70 else (ConfidenceBand.GRAY if max_semantic_score >= 0.30 else ConfidenceBand.CLEAR_LOW),
                    reason_codes=list(semantic_scores.keys()),
                ),
                jailbreak=DetectionSignal(
                    detector_id="jailbreak_detector",
                    raw_score=round(max(jailbreak_findings.values(), default=0.0), 4),
                    score_type=ScoreType.HEURISTIC,
                    reason_codes=list(jailbreak_findings.keys()),
                ),
                role_override=DetectionSignal(
                    detector_id="role_override_detector",
                    raw_score=round(semantic_scores.get("role_override", 0.0), 4),
                    score_type=ScoreType.SIMILARITY,
                ),
                system_prompt_extraction=DetectionSignal(
                    detector_id="system_prompt_extraction_detector",
                    raw_score=round(max(semantic_scores.get("system_prompt_extraction", 0.0), 0.95 if any("leak" in r.lower() or "prompt" in r.lower() for r in matched_rule_names) else 0.0), 4),
                    score_type=ScoreType.HEURISTIC,
                ),
                tool_schema_extraction=DetectionSignal(
                    detector_id="tool_schema_extraction_detector",
                    raw_score=round(semantic_scores.get("tool_schema_extraction", 0.0), 4),
                    score_type=ScoreType.HEURISTIC,
                ),
                obfuscation=DetectionSignal(
                    detector_id="obfuscation_detector",
                    raw_score=1.0 if script_profile.obfuscation_types else 0.0,
                    score_type=ScoreType.HEURISTIC,
                    reason_codes=script_profile.obfuscation_types,
                ),
            )

            # 4. Content Risk & Cyber Intent Rail
            safety_findings: dict[str, float] = {}
            for variant_text, source_tag in variants:
                sf_res = self.safety_detector.evaluate(variant_text)
                safety_findings.update(sf_res)

            content_risk = ContentRiskEvidence(
                unauthorized_cyber_intent=DetectionSignal(
                    detector_id="content_risk.cyber_intent",
                    raw_score=round(max_rule_score if any("attack" in r.lower() or "sql" in r.lower() or "cve" in r.lower() for r in matched_rule_names) else 0.0, 4),
                    score_type=ScoreType.HEURISTIC,
                ),
                safety_hazards={
                    k: DetectionSignal(detector_id=f"safety.{k}", raw_score=round(v, 4), score_type=ScoreType.HEURISTIC)
                    for k, v in safety_findings.items()
                },
            )

            # 5. DLP / Secrets & Invariant Rail
            pii_findings: dict[str, float] = {}
            dlp_findings: dict[str, float] = {}
            for variant_text, source_tag in variants:
                pii_findings.update(self.pii_detector.evaluate(variant_text))
                dlp_findings.update(self.dlp_validator.evaluate(variant_text))

            has_creds = any("key" in k.lower() or "secret" in k.lower() or "token" in k.lower() for k in dlp_findings)
            has_pii = len(pii_findings) > 0

            dlp = DlpEvidence(
                has_credentials=has_creds,
                has_pii=has_pii,
                hard_invariant_violation=has_creds or any(m.severity.score >= 0.9 for m in rule_matches if "secret" in m.rule_name.lower()),
                matched_secrets=list(dlp_findings.keys()),
                matched_pii_types=list(pii_findings.keys()),
            )

            # 6. Context & Multi-turn Trajectory
            context_scores = self.context_analyzer.evaluate(messages or [])
            context = ContextEvidence(
                multi_turn_depth=len(messages) if messages else 0,
                cumulative_assembly_detected=bool(context_scores.get("salami_attack", 0.0) > 0.5),
            )

            # 7. Auxiliary Signals (BM25 Similarity & Statistical Features)
            # IMPORTANT: BM25 is treated as an auxiliary feature, not an authoritative routing decision.
            lexical_scores: dict[str, float] = {}
            for variant_text, source_tag in variants:
                lx_res = self.lexical_engine.evaluate_lexical(variant_text)
                lexical_scores.update(lx_res)

            auxiliary = AuxiliaryEvidence(
                known_attack_similarity=round(lexical_scores.get("lexical_bm25_threat", 0.0), 4),
                shannon_entropy=round(self.defenseclaw_metrics.extract_metrics(text).shannon_entropy, 4),
                zero_width_count=len(script_meta.get("obfuscation_types", [])),
            )

            total_latency = (time.perf_counter() - start_time) * 1000.0

            evidence = SecurityEvidence(
                canonical_text=canonical_text,
                raw_prompt_hash=prompt_hash,
                prompt_attack=prompt_attack,
                content_risk=content_risk,
                dlp=dlp,
                context=context,
                script_profile=script_profile,
                auxiliary=auxiliary,
                total_latency_ms=round(total_latency, 2),
                detector_status=detector_status,
                all_reasons=all_reasons + list(jailbreak_findings.keys()) + list(safety_findings.keys()),
            )

            metadata_scores = self.metadata_analyzer.evaluate(metadata)
            specialized_scores = {
                **{f"pii_{key}": value for key, value in pii_findings.items()},
                **{f"jailbreak_{key}": value for key, value in jailbreak_findings.items()},
                **{f"safety_{key}": value for key, value in safety_findings.items()},
            }
            aggregate = self.risk_aggregator.aggregate(
                rule_matches=rule_matches,
                semantic_scores=semantic_scores,
                context_scores=context_scores,
                metadata_scores=metadata_scores,
                specialized_scores=specialized_scores,
                caller_metadata=metadata,
            )
            evidence.classification = aggregate.classification
            evidence.reasons_list = aggregate.reasons
            evidence.categories_dict = aggregate.categories
            detector_status["risk_aggregator"] = "active"

            return evidence

        except Exception as err:
            logger.error("ClassifierService encountered fatal error: %s -> Emitting Fail-Closed Evidence", err)
            return SecurityEvidence(
                canonical_text=text,
                raw_prompt_hash="",
                dlp=DlpEvidence(hard_invariant_violation=True),
                detector_status={"gateway": "errored"},
                all_reasons=[f"fail_closed_error: {err}"],
                classification=Classification.RESTRICTED,
            )

    def reload_rules(self, rules_dir: str) -> None:
        """Hot-reload rules from disk."""
        self.rule_engine.reload(rules_dir)
        logger.info("Rules reloaded, total: %d", len(self.rule_engine.rules))
