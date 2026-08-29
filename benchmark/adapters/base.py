"""
Abstract Detector Adapter Interface for Phase 2 Benchmarking.

Any candidate detector (Current C0, Prompt Guard 2, Qwen3Guard, XLM-R, Custom)
must implement this interface to be evaluated seamlessly by the Benchmark Harness.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from benchmark.schema import BenchmarkSample
from classifier.evidence_models import SecurityEvidence


class BaseDetectorAdapter(ABC):
    """Abstract model-agnostic security detector adapter."""

    def __init__(self, adapter_id: str, adapter_version: str = "1.0") -> None:
        self.adapter_id = adapter_id
        self.adapter_version = adapter_version

    @abstractmethod
    def detect(self, sample: BenchmarkSample) -> SecurityEvidence:
        """
        Execute detector on the given sample and emit standardized SecurityEvidence.
        Must NOT perform policy routing decisions.
        """
        pass
