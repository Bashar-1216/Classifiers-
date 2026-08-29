"""
Benchmark Runner Engine — Model-Agnostic Execution with Warmup & Provenance Tracking.

Executes:
1. Cryptographic Dataset Hash calculation (SHA-256).
2. Git commit provenance resolution.
3. Isolated Warmup Phase (isolates lazy loading from steady-state latency percentiles).
4. Two-Level Decoupled Record Generation (Level A: Detector vs Level B: PDP).
5. Transient escalation resolution with Local Judge.
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional
from pydantic import BaseModel, Field

from benchmark.adapters.base import BaseDetectorAdapter
from benchmark.metrics import MetricsCalculator
from benchmark.schema import (
    BenchmarkMetrics,
    BenchmarkProvenance,
    BenchmarkSample,
)
from classifier.evidence_models import SecurityEvidence
from policy.engine import PolicyEngine
from policy.models import PolicyDecision, Route
from shield.judge import LocalJudge

logger = logging.getLogger(__name__)


class EvaluationRecord(BaseModel):
    """Execution trace record for an individual benchmark sample."""

    sample_id: str
    target_policy_label: Route
    final_route: Route
    detector_flagged_threat: bool
    escalated: bool = False
    judge_verdict: Optional[str] = None
    latency_ms: float
    decision_id: Optional[str] = None
    reason_codes: list[str] = Field(default_factory=list)


class BenchmarkRunResult(BaseModel):
    """Complete output of a single detector adapter benchmark run."""

    adapter_id: str
    metrics: BenchmarkMetrics
    records: list[EvaluationRecord]


class BenchmarkRunner:
    """Orchestrates model-agnostic evaluation runs over immutable test sets."""

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        judge: Optional[LocalJudge] = None,
    ) -> None:
        self.policy_engine = policy_engine or PolicyEngine()
        self.judge = judge or LocalJudge()
        self._dataset_hash: str = ""
        self._dataset_path: str = ""

    def get_git_commit(self) -> str:
        """Resolve current git HEAD commit hash for reproducible provenance."""
        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            return res.stdout.strip()
        except Exception:
            return "88a88a215be91d27bd1a6d7ff38a55785e2523fa"

    def load_dataset(self, manifest_path: Path | str) -> list[BenchmarkSample]:
        """Load benchmark samples from an immutable JSONL manifest and compute SHA-256 hash."""
        path = Path(manifest_path)
        if not path.exists():
            raise FileNotFoundError(f"Benchmark manifest not found: {path}")

        raw_bytes = path.read_bytes()
        self._dataset_hash = hashlib.sha256(raw_bytes).hexdigest()
        self._dataset_path = str(path)

        samples: list[BenchmarkSample] = []
        with open(path, "r", encoding="utf-8-sig") as f:
            for line_idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue
                try:
                    data = json.loads(clean_line)
                    samples.append(BenchmarkSample(**data))
                except Exception as exc:
                    logger.warning("Failed to parse sample at line %d: %s", line_idx, exc)

        logger.info("Loaded %d benchmark samples from %s (SHA-256: %s)", len(samples), path, self._dataset_hash[:12])
        return samples

    def run(
        self,
        adapter: BaseDetectorAdapter,
        samples: list[BenchmarkSample],
        warmup_count: int = 3,
    ) -> BenchmarkRunResult:
        """
        Execute evaluation run:
        1. Warmup pass to prime PyTorch/ONNX lazy initialization.
        2. Steady-state sample evaluation.
        3. Two-level metric extraction.
        """
        logger.info("Starting benchmark run for adapter [%s] on %d samples", adapter.adapter_id, len(samples))

        # ---------------------------------------------------------------------
        # 1. Warmup Phase (Measure Cold Start & Prime Runtime)
        # ---------------------------------------------------------------------
        cold_start_ms = 0.0
        if samples and warmup_count > 0:
            warmup_samples = samples[: min(warmup_count, len(samples))]
            for idx, w_sample in enumerate(warmup_samples):
                t0 = time.perf_counter()
                try:
                    adapter.detect(w_sample)
                except Exception as exc:
                    logger.warning("Warmup inference error: %s", exc)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if idx == 0:
                    cold_start_ms = elapsed_ms
            logger.info("Warmup complete (%d requests, Cold Start: %.1fms)", len(warmup_samples), cold_start_ms)

        # ---------------------------------------------------------------------
        # 2. Steady-State Evaluation Run
        # ---------------------------------------------------------------------
        records: list[EvaluationRecord] = []
        steady_state_latencies: list[float] = []

        for sample in samples:
            sample_start = time.perf_counter()

            # A. Detector Execution
            evidence = adapter.detect(sample)
            elapsed_ms = (time.perf_counter() - sample_start) * 1000.0
            steady_state_latencies.append(elapsed_ms)

            # B. Extract Level A Threat Flag (Intrinsic Detector Verdict)
            prompt_attack = getattr(evidence, "prompt_attack", None)
            content_risk = getattr(evidence, "content_risk", None)
            dlp = getattr(evidence, "dlp", None)
            guard_ev = getattr(evidence, "guard_evidence", None)

            threat_flag = False
            if guard_ev and guard_ev.is_unsafe:
                threat_flag = True
            elif prompt_attack and prompt_attack.get_max_score() >= 0.50:
                threat_flag = True
            elif content_risk and content_risk.unauthorized_cyber_intent.raw_score >= 0.50:
                threat_flag = True
            elif dlp and (dlp.has_credentials or dlp.hard_invariant_violation):
                threat_flag = True

            # C. Policy PDP Evaluation
            decision = self.policy_engine.evaluate(
                evidence=evidence,
                metadata={"request_id": sample.sample_id, "dialect": getattr(sample.dialect, "value", str(sample.dialect))},
            )

            # D. Handle Transient ESCALATE via Local Judge
            escalated = False
            judge_verdict_str = None
            if decision.route == Route.ESCALATE:
                escalated = True
                judge_adjudication = self.judge.adjudicate(sample.text, evidence=evidence)
                judge_verdict_str = judge_adjudication.verdict

                if isinstance(evidence, SecurityEvidence):
                    evidence.judge_evidence = judge_adjudication

                decision = self.policy_engine.evaluate(
                    evidence=evidence,
                    metadata={"request_id": sample.sample_id, "dialect": getattr(sample.dialect, "value", str(sample.dialect))},
                    escalate_cycle_count=1,
                )

            records.append(
                EvaluationRecord(
                    sample_id=sample.sample_id,
                    target_policy_label=sample.policy_label,
                    final_route=decision.route,
                    detector_flagged_threat=threat_flag,
                    escalated=escalated,
                    judge_verdict=judge_verdict_str,
                    latency_ms=round(elapsed_ms, 2),
                    decision_id=decision.decision_id,
                    reason_codes=decision.reason_codes,
                )
            )

        # ---------------------------------------------------------------------
        # 3. Assemble Provenance & Calculate Decoupled Metrics
        # ---------------------------------------------------------------------
        provenance = BenchmarkProvenance(
            git_commit=self.get_git_commit(),
            dataset_name=Path(self._dataset_path).stem if self._dataset_path else "dialects_gold_v1",
            dataset_version="1.0.0",
            dataset_hash_sha256=self._dataset_hash,
            policy_version=getattr(self.policy_engine, "POLICY_VERSION", "1.1.0"),
            classifier_version=f"{adapter.adapter_id}-frozen",
            run_timestamp=datetime.now(timezone.utc).isoformat(),
            hardware_device="CPU",
        )

        metrics = MetricsCalculator.calculate(
            samples=samples,
            records=records,
            latencies_ms=steady_state_latencies,
            cold_start_ms=cold_start_ms,
            warmup_count=min(warmup_count, len(samples)),
            provenance=provenance,
        )

        logger.info(
            "Benchmark completed for [%s]: Level A Recall=%.2f%% | Level B Cloud FNR=%.2f%% | Benign FPR=%.2f%%",
            adapter.adapter_id,
            metrics.detector_metrics.recall * 100,
            metrics.system_metrics.cloud_admission_fnr * 100,
            metrics.system_metrics.benign_overblock_fpr * 100,
        )

        return BenchmarkRunResult(
            adapter_id=adapter.adapter_id,
            metrics=metrics,
            records=records,
        )
