"""
AI Risk Assessment Layer — Main Orchestrator (ClassifierService).

Unified Architecture combining Intelligence from:
  1. System Prompts & Agent Architectures (What to protect)
  2. vLLM Semantic Router (How to detect & route: Lexical + Structure + Fail-Closed)

Orchestrates Multi-Signal Layers:
  - Lexical Signal Engine (Exact, Regex, BM25, Subword Character N-Grams)
  - Structure Signal Engine (Keyword Density, Sequence Ordering, Containers)
  - Semantic Vector Classifier (Contrastive Latent Embeddings)
  - Specialized Classifiers (PII, Jailbreak, Safety)
  - Context & Metadata Analyzers (Multi-turn & Role Verification)
  - Strict Fail-Closed Error Handling Guarantee
"""

from __future__ import annotations

import logging
from typing import Any

from classifier.context_analyzer import ContextAnalyzer
from classifier.lexical_engine import LexicalSignalEngine
from classifier.metadata_analyzer import MetadataAnalyzer
from classifier.models import Classification, ClassificationResult, RuleMatch
from classifier.normalizer import TextNormalizer
from classifier.risk_aggregator import RiskAggregator
from classifier.rule_engine import RuleEngine
from classifier.semantic_classifier import SemanticClassifier
from classifier.structure_engine import StructureSignalEngine
from risk_engine.specialized import JailbreakDetector, PIIDetector, SafetyDetector

logger = logging.getLogger(__name__)

DEFAULT_CONFIDENCE_THRESHOLD = 0.50


class ClassifierService:
    """
    Multi-Signal Risk Assessment & Security Gateway.
    Orchestrates Lexical, Structural, Semantic, Specialized, and Contextual evaluations.
    Guarantees strict Fail-Closed behavior on any subsystem error.
    """

    def __init__(
        self,
        rules_dir: str | None = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ) -> None:
        self.rule_engine = RuleEngine(rules_dir)
        self.lexical_engine = LexicalSignalEngine()
        self.structure_engine = StructureSignalEngine()
        self.semantic_classifier = SemanticClassifier()
        self.pii_detector = PIIDetector()
        self.jailbreak_detector = JailbreakDetector()
        self.safety_detector = SafetyDetector()
        self.context_analyzer = ContextAnalyzer()
        self.metadata_analyzer = MetadataAnalyzer()
        self.risk_aggregator = RiskAggregator(confidence_threshold=confidence_threshold)
        self.confidence_threshold = confidence_threshold

        logger.info(
            "Multi-Signal Risk Assessment Layer initialized (Lexical, Structure, Semantic, Specialized, Context, Metadata, and %d Rules).",
            len(self.rule_engine.rules),
        )

    def classify(
        self,
        text: str,
        messages: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ClassificationResult:
        """
        Perform multi-dimensional risk assessment with strict Fail-Closed guarantee.

        Args:
            text: The full aggregated text of the user request.
            messages: Optional conversation messages list for multi-turn context analysis.
            metadata: Optional caller metadata (user role, department, data sensitivity).

        Returns:
            ClassificationResult produced by the Risk Aggregator (or FAIL-CLOSED on error).
        """
        if not text or not text.strip():
            return ClassificationResult(
                classification=Classification.NORMAL,
                confidence=0.0,
                risk_score=0.0,
                reasons=[],
                matched_rules=[],
            )

        try:
            # 1. Deterministic Rule Matching on all de-obfuscated variants
            variants = TextNormalizer.get_all_normalized_variants(text)
            rule_matches: list[RuleMatch] = []
            matched_rule_names = set()

            for variant_text, source_tag in variants:
                matches = self.rule_engine.evaluate(variant_text)
                for m in matches:
                    if m.rule_name not in matched_rule_names:
                        matched_rule_names.add(m.rule_name)
                        if source_tag != "direct_text":
                            rule_matches.append(
                                RuleMatch(
                                    rule_name=f"{m.rule_name} [{source_tag}]",
                                    pattern_matched=m.pattern_matched,
                                    severity=m.severity,
                                    match_type=m.match_type,
                                )
                            )
                        else:
                            rule_matches.append(m)

            # 2. Structural Signal Engine (Density & Sequence)
            structure_scores: dict[str, float] = {}
            for variant_text, source_tag in variants:
                st_scores = self.structure_engine.evaluate_structure(variant_text)
                for cat, score in st_scores.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    structure_scores[tag_name] = max(structure_scores.get(tag_name, 0.0), score)

            # 3. Lexical Signal Engine (BM25 + Subword N-Grams)
            lexical_scores: dict[str, float] = {}
            for variant_text, source_tag in variants:
                lx_scores = self.lexical_engine.evaluate_lexical(variant_text)
                for cat, score in lx_scores.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    lexical_scores[tag_name] = max(lexical_scores.get(tag_name, 0.0), score)

            # 4. Semantic Vector Classifier (Contrastive Intent & Nuance)
            semantic_scores: dict[str, float] = {}
            for variant_text, source_tag in variants:
                v_scores = self.semantic_classifier.evaluate(variant_text)
                for cat, score in v_scores.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    semantic_scores[tag_name] = max(semantic_scores.get(tag_name, 0.0), score)

            # 5. Specialized Classifiers (PII, Jailbreak, Safety)
            specialized_scores: dict[str, float] = {}
            for variant_text, source_tag in variants:
                # PII
                pii_res = self.pii_detector.evaluate(variant_text)
                for cat, score in pii_res.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    specialized_scores[tag_name] = max(specialized_scores.get(tag_name, 0.0), score)

                # Jailbreak
                jb_res = self.jailbreak_detector.evaluate(variant_text)
                for cat, score in jb_res.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    specialized_scores[tag_name] = max(specialized_scores.get(tag_name, 0.0), score)

                # Safety
                safe_res = self.safety_detector.evaluate(variant_text)
                for cat, score in safe_res.items():
                    tag_name = f"{cat} [{source_tag}]" if source_tag != "direct_text" else cat
                    specialized_scores[tag_name] = max(specialized_scores.get(tag_name, 0.0), score)

            # Combine lexical and structural scores into specialized pool
            specialized_scores.update(structure_scores)
            specialized_scores.update(lexical_scores)

            # 6. Context & Metadata Analyzers
            context_scores = self.context_analyzer.evaluate(messages or [])
            metadata_scores = self.metadata_analyzer.evaluate(metadata or {})

            # 7. Synthesize in Risk Aggregation Engine
            result = self.risk_aggregator.aggregate(
                rule_matches=rule_matches,
                semantic_scores=semantic_scores,
                context_scores=context_scores,
                metadata_scores=metadata_scores,
                specialized_scores=specialized_scores,
                caller_metadata=metadata,
            )

            logger.info(
                "Risk Assessment: %s (confidence=%.4f, risk_score=%.4f, reasons=%s)",
                result.classification.value,
                result.confidence,
                result.risk_score,
                result.reasons,
            )

            return result

        except Exception as err:
            # STRICT FAIL-CLOSED ON ERROR (Inspired by vLLM semantic-router onerror-block)
            logger.error("ClassifierService encountered fatal error: %s -> Enforcing FAIL-CLOSED (RESTRICTED)", err)
            return ClassificationResult(
                classification=Classification.RESTRICTED,
                confidence=1.0,
                risk_score=1.0,
                reasons=[f"fail_closed_error: {err}"],
                matched_rules=[],
            )

    def reload_rules(self, rules_dir: str) -> None:
        """Hot-reload rules from disk."""
        self.rule_engine.reload(rules_dir)
        logger.info("Rules reloaded, total: %d", len(self.rule_engine.rules))
