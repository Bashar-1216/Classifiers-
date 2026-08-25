"""
AI Risk Assessment Package.

Core Components:
- ClassifierService: Central Risk Assessment Layer Orchestrator
- SemanticClassifier: Semantic Intent & Nuance Analyzer
- ContextAnalyzer: Multi-turn History Trajectory Analyzer
- MetadataAnalyzer: User Role & Privilege Boundary Evaluator
- RiskAggregator: Multi-Dimensional Risk Synthesis Engine
- TextNormalizer: De-obfuscation & Anti-Evasion Normalizer
- RuleEngine: Deterministic Signature Matcher
"""

from __future__ import annotations

from classifier.context_analyzer import ContextAnalyzer
from classifier.metadata_analyzer import MetadataAnalyzer
from classifier.models import Classification, ClassificationResult, RuleMatch, RuleType, Severity
from classifier.normalizer import TextNormalizer
from classifier.risk_aggregator import RiskAggregator
from classifier.rule_engine import RuleEngine
from classifier.semantic_classifier import SemanticClassifier
from classifier.service import ClassifierService

__all__ = [
    "ClassifierService",
    "SemanticClassifier",
    "ContextAnalyzer",
    "MetadataAnalyzer",
    "RiskAggregator",
    "TextNormalizer",
    "RuleEngine",
    "Classification",
    "ClassificationResult",
    "RuleMatch",
    "RuleType",
    "Severity",
]
