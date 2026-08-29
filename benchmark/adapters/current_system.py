"""
Current Production System Adapter (C0 Baseline).
"""

from __future__ import annotations

from benchmark.adapters.base import BaseDetectorAdapter
from benchmark.schema import BenchmarkSample
from classifier.evidence_models import SecurityEvidence
from classifier.service import ClassifierService


class CurrentSystemAdapter(BaseDetectorAdapter):
    """Evaluates the existing production detector pipeline."""

    def __init__(self, rules_dir: str | None = None) -> None:
        super().__init__(adapter_id="current_system_c0", adapter_version="2.4")
        self.classifier = ClassifierService(rules_dir=rules_dir)

    def detect(self, sample: BenchmarkSample) -> SecurityEvidence:
        dialect_str = sample.dialect.value if hasattr(sample.dialect, "value") else str(sample.dialect)
        return self.classifier.classify(
            sample.text,
            messages=getattr(sample, "context_messages", None),
            metadata={"request_id": sample.sample_id, "dialect": dialect_str},
        )
