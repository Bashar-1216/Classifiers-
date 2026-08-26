"""
AI Risk Assessment Layer — Main Orchestrator (ClassifierService).

Thin Pipeline Architecture:
  Step 1: Normalization & De-obfuscation (TextNormalizer)
  Step 2: Fast Lexical Rules (RuleEngine & LexicalSignalEngine)
  Step 3: Statistical Signals (DefenseClawMetrics & StructureSignalEngine)
  Step 4: Semantic Guard (SemanticClassifier)
  Step 5: Specialized Detectors & DLP (PII, Jailbreak, Safety, DLPValidator)
  Step 6: Abstract Risk Axes Correlation (RiskAxesCorrelator)
  Step 7: Conditional Local Adjudication (LocalRiskAdjudicator on conflict only)
  Step 8: Output standardized RiskEvidence vector (with Fail-Closed guarantee)
"""

from __future__ import annotations

import logging
from typing import Any

from classifier.context_analyzer import ContextAnalyzer
from classifier.defenseclaw_metrics import DefenseClawMetrics
from classifier.lexical_engine import LexicalSignalEngine
from classifier.knowledge_loader import SecurityKnowledgeBundle
from classifier.local_adjudicator import LocalRiskAdjudicator
from classifier.metadata_analyzer import MetadataAnalyzer
from classifier.models import Classification, DetectionResult, RiskEvidence, RuleMatch
from classifier.normalizer import TextNormalizer
from classifier.risk_aggregator import RiskAggregator
from classifier.risk_correlator import RiskAxesCorrelator
from classifier.rule_engine import RuleEngine
from classifier.semantic_classifier import SemanticClassifier
from classifier.structure_engine import StructureSignalEngine
from risk_engine.specialized import JailbreakDetector, PIIDetector, SafetyDetector
from risk_engine.specialized.dlp_validator import DLPValidator

logger = logging.getLogger(__name__)

DEFAULT_CONFIDENCE_THRESHOLD = 0.50


class ClassifierService:
    """
    Multi-Signal Risk Assessment & Security Gateway Orchestrator.
    Executes a modular multi-tier evaluation and produces standardized RiskEvidence.
    Guarantees strict Fail-Closed behavior on any subsystem exception.
    """

    def __init__(
        self,
        rules_dir: str | None = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        knowledge_dir: str | None = None,
    ) -> None:
        self.knowledge_bundle = SecurityKnowledgeBundle(knowledge_dir)
        self.knowledge_bundle.validate()
        # Fast Lexical & Deterministic Rules
        effective_rules_dir = rules_dir or str(
            self.knowledge_bundle.source_path("ingress_default").parent
        )
        self.rule_engine = RuleEngine(effective_rules_dir)
        self.lexical_engine = LexicalSignalEngine(self.knowledge_bundle)

        # Structural & Statistical Metrics
        self.structure_engine = StructureSignalEngine()
        self.defenseclaw_metrics = DefenseClawMetrics()

        # Semantic & Specialized Guardrails
        self.semantic_classifier = SemanticClassifier(knowledge_bundle=self.knowledge_bundle)
        self.pii_detector = PIIDetector()
        self.jailbreak_detector = JailbreakDetector()
        self.safety_detector = SafetyDetector()
        self.dlp_validator = DLPValidator(self.knowledge_bundle)

        # Context, Metadata, Correlation & Adjudication
        self.context_analyzer = ContextAnalyzer(knowledge_bundle=self.knowledge_bundle)
        self.metadata_analyzer = MetadataAnalyzer()
        self.risk_correlator = RiskAxesCorrelator()
        self.local_adjudicator = LocalRiskAdjudicator(self.knowledge_bundle)

        self.risk_aggregator = RiskAggregator(confidence_threshold=confidence_threshold)
        self.confidence_threshold = confidence_threshold

        logger.info(
            "ClassifierService initialized with knowledge bundle %s (%s) and %d rules.",
            self.knowledge_bundle.version,
            self.knowledge_bundle.bundle_hash[:12],
            len(self.rule_engine.rules),
        )

    def classify(
        self,
        text: str,
        messages: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RiskEvidence:
        """
        Execute risk assessment pipeline and produce structured RiskEvidence.
        """
        if not text or not text.strip():
            return RiskEvidence(
                classification=Classification.NORMAL,
                confidence=0.0,
                risk_score=0.0,
                reasons=[],
                matched_rules=[],
                categories={},
                detections=[],
                correlations=[],
                uncertainty=0.0,
                detector_status={"gateway": "idle"},
            )

        try:
            detections: list[DetectionResult] = []
            detector_status: dict[str, str] = {}

            # 1. Normalization & De-obfuscation
            variants = TextNormalizer.get_all_normalized_variants(text)

            # 2. Fast Deterministic Rule Matching
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
                        detections.append(
                            DetectionResult(
                                detector="rule_engine",
                                categories=["security"],
                                score=m.severity.score,
                                confidence=m.severity.score,
                                status="triggered",
                                evidence={"rule": m.rule_name, "pattern": m.pattern_matched},
                                version="2.4",
                            )
                        )
            detector_status["rule_engine"] = "active"

            # 3. Raw Statistical & Structural Signals (DefenseClaw & Structure)
            raw_metrics = self.defenseclaw_metrics.extract_metrics(text)
            structural_scores: dict[str, float] = {}

            # Corroborate raw metrics: high density or mixed scripts generate signal
            if raw_metrics.imperative_density >= 0.25 and raw_metrics.imperative_count >= 2:
                structural_scores["defenseclaw_imperative_density"] = min(0.95, 0.60 + (raw_metrics.imperative_density * 0.8))
            if raw_metrics.mixed_script:
                structural_scores["defenseclaw_mixed_script_tampering"] = 0.95
            if raw_metrics.encoding_suspected:
                structural_scores["defenseclaw_high_entropy_obfuscation"] = 0.85

            for variant_text, source_tag in variants:
                st_scores = self.structure_engine.evaluate_structure(variant_text)
                for cat, score in st_scores.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    structural_scores[tag_name] = max(structural_scores.get(tag_name, 0.0), score)

            # 4. Fast Lexical Engine (BM25 + Subword N-grams)
            lexical_scores: dict[str, float] = {}
            for variant_text, source_tag in variants:
                lx_scores = self.lexical_engine.evaluate_lexical(variant_text)
                for cat, score in lx_scores.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    lexical_scores[tag_name] = max(lexical_scores.get(tag_name, 0.0), score)
            detector_status["lexical_engine"] = "active"

            # 5. Semantic Vector Guard (Contrastive Intent)
            semantic_scores: dict[str, float] = {}
            max_semantic_score = 0.0
            for variant_text, source_tag in variants:
                v_scores = self.semantic_classifier.evaluate(variant_text)
                for cat, score in v_scores.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    semantic_scores[tag_name] = max(semantic_scores.get(tag_name, 0.0), score)
                    max_semantic_score = max(max_semantic_score, score)
            detector_status["semantic_guard"] = "active"

            # 6. Specialized Detectors & Strict DLP Checksums
            specialized_scores: dict[str, float] = {}
            for variant_text, source_tag in variants:
                specialized_scores.update(self.pii_detector.evaluate(variant_text))
                specialized_scores.update(self.jailbreak_detector.evaluate(variant_text))
                specialized_scores.update(self.safety_detector.evaluate(variant_text))
                specialized_scores.update(self.dlp_validator.evaluate(variant_text))

            specialized_scores.update(structural_scores)
            specialized_scores.update(lexical_scores)
            detector_status["specialized_detectors"] = "active"

            # 7. Multi-Axis Threat Correlation (Abstract Axes)
            correlations_raw = self.risk_correlator.correlate(
                rule_reasons=[m.rule_name for m in rule_matches],
                specialized_reasons=list(specialized_scores.keys()),
                semantic_categories=semantic_scores,
                caller_metadata=metadata,
            )
            correlations_dict = [
                {"correlation": c.correlation, "score": c.score, "axes": c.axes, "description": c.description}
                for c in correlations_raw
            ]
            for c in correlations_raw:
                specialized_scores[f"correlation_{c.correlation}"] = c.score

            # 8. Context & Metadata Analyzers
            context_scores = self.context_analyzer.evaluate(messages or [])
            metadata_scores = self.metadata_analyzer.evaluate(metadata or {})

            # 9. Risk Synthesis via Aggregator
            preliminary = self.risk_aggregator.aggregate(
                rule_matches=rule_matches,
                semantic_scores=semantic_scores,
                context_scores=context_scores,
                metadata_scores=metadata_scores,
                specialized_scores=specialized_scores,
                caller_metadata=metadata,
            )

            # 10. Conditional Local Risk Adjudication (Only upon conflict / uncertainty)
            final_risk_score = preliminary.confidence
            final_reasons = preliminary.reasons
            uncertainty = round(abs(max_rule_score - max_semantic_score), 4)

            if preliminary.confidence > 0.0:
                adjudicated_score, adjudicated_reasons, was_adjudicated = self.local_adjudicator.adjudicate(
                    text=text,
                    initial_risk_score=preliminary.confidence,
                    rule_score=max_rule_score,
                    semantic_score=max_semantic_score,
                    uncertainty=uncertainty,
                    reasons=preliminary.reasons,
                )
                if was_adjudicated and adjudicated_score == 0.0:
                    final_risk_score = 0.0
                    final_reasons = []

            final_classification = Classification.RESTRICTED if final_risk_score >= self.confidence_threshold else Classification.NORMAL

            evidence = RiskEvidence(
                classification=final_classification,
                confidence=round(final_risk_score, 4),
                risk_score=round(final_risk_score, 4),
                categories=preliminary.categories,
                reasons=final_reasons,
                matched_rules=rule_matches if final_risk_score > 0 else [],
                detections=detections,
                correlations=correlations_dict,
                uncertainty=uncertainty,
                detector_status=detector_status,
            )

            logger.info(
                "Risk Assessment Complete: %s (confidence=%.4f, reasons=%s)",
                evidence.classification.value,
                evidence.confidence,
                evidence.reasons,
            )
            return evidence

        except Exception as err:
            logger.error("ClassifierService encountered fatal error: %s -> FAIL-CLOSED (RESTRICTED)", err)
            return RiskEvidence(
                classification=Classification.RESTRICTED,
                confidence=1.0,
                risk_score=1.0,
                categories={"security": 1.0},
                reasons=[f"fail_closed_error: {err}"],
                matched_rules=[],
                detections=[],
                correlations=[],
                uncertainty=1.0,
                detector_status={"gateway": "errored"},
            )

    def reload_rules(self, rules_dir: str) -> None:
        """Hot-reload rules from disk."""
        self.rule_engine.reload(rules_dir)
        logger.info("Rules reloaded, total: %d", len(self.rule_engine.rules))
