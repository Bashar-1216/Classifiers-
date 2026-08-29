"""
Benchmark Metrics Calculator — Two-Level Decoupled Scientific Evaluation.

Computes:
1. Level A (Detector Performance): Standalone Detector Recall, Precision, F1, FPR, FNR.
2. Level B (System Performance): End-to-End Cloud Admission FNR, Benign Overblocking FPR, Block Recall.
3. Dialect, Domain, Hard-Negative, and Obfuscation Slices.
4. Cold-Start vs Warm Steady-State Latency Percentiles.
"""

from __future__ import annotations

import math
from typing import Any, List
from policy.models import Route
from benchmark.schema import (
    BenchmarkLatencyMetrics,
    BenchmarkMetrics,
    BenchmarkProvenance,
    BenchmarkSample,
    DetectorMetrics,
    SliceMetrics,
    SystemMetrics,
)


class MetricsCalculator:
    """Computes comprehensive two-level benchmark metrics across stratified slices."""

    @classmethod
    def calculate(
        cls,
        samples: list[BenchmarkSample],
        records: list[Any],
        latencies_ms: list[float],
        cold_start_ms: float = 0.0,
        warmup_count: int = 0,
        provenance: BenchmarkProvenance | None = None,
    ) -> BenchmarkMetrics:
        """Calculate complete benchmark metrics object from execution records."""
        sample_map = {s.sample_id: s for s in samples}

        # ---------------------------------------------------------------------
        # 1. Level A: Standalone Detector Metric Accumulators
        # ---------------------------------------------------------------------
        det_tp = 0
        det_fp = 0
        det_tn = 0
        det_fn = 0

        # ---------------------------------------------------------------------
        # 2. Level B: End-to-End System PDP Metric Accumulators
        # ---------------------------------------------------------------------
        sys_restricted_actual = 0
        sys_restricted_missed_fn = 0  # Restricted samples that leaked to NORMAL (Cloud Admission)
        sys_benign_actual = 0
        sys_benign_false_alarm_fp = 0  # Benign samples routed to RESTRICTED/BLOCK/SHIELD
        sys_block_actual = 0
        sys_block_correct = 0
        sys_escalations = 0

        route_distribution: dict[str, int] = {}

        # Slices maps: key -> (det_tp, det_fp, det_tn, det_fn, sys_restr, sys_restr_fn, sys_benign, sys_benign_fp)
        dialect_data: dict[str, list[int]] = {}
        domain_data: dict[str, list[int]] = {}
        hard_neg_data = [0, 0, 0, 0, 0, 0, 0, 0]
        obfuscation_data = [0, 0, 0, 0, 0, 0, 0, 0]

        for record in records:
            sample = sample_map.get(record.sample_id)
            if not sample:
                continue

            final_route = record.final_route
            route_distribution[final_route.value] = route_distribution.get(final_route.value, 0) + 1

            if getattr(record, "escalated", False):
                sys_escalations += 1

            is_actual_threat = sample.policy_label in (Route.RESTRICTED, Route.BLOCK, Route.SHIELD)
            is_actual_block = sample.policy_label == Route.BLOCK
            is_actual_benign = sample.policy_label == Route.NORMAL

            # Level A Detector Verdict: evidence detected hazard
            detector_reported_threat = getattr(record, "detector_flagged_threat", False)

            if is_actual_threat:
                if detector_reported_threat:
                    det_tp += 1
                else:
                    det_fn += 1
            else:
                if detector_reported_threat:
                    det_fp += 1
                else:
                    det_tn += 1

            # Level B System PDP Verdict
            sys_is_cloud_normal = final_route == Route.NORMAL
            sys_is_restricted_or_block = final_route in (Route.RESTRICTED, Route.BLOCK, Route.SHIELD, Route.LOCAL_SHIELD)

            if is_actual_threat:
                sys_restricted_actual += 1
                if sys_is_cloud_normal:
                    sys_restricted_missed_fn += 1

            if is_actual_block:
                sys_block_actual += 1
                if final_route == Route.BLOCK:
                    sys_block_correct += 1

            if is_actual_benign:
                sys_benign_actual += 1
                if sys_is_restricted_or_block:
                    sys_benign_false_alarm_fp += 1

            # Dialect slice accumulation
            dialect_key = sample.dialect.value if hasattr(sample.dialect, "value") else str(sample.dialect)
            cls._accumulate_slice(
                slice_map=dialect_data,
                key=dialect_key,
                is_threat=is_actual_threat,
                is_benign=is_actual_benign,
                det_threat=detector_reported_threat,
                sys_normal=sys_is_cloud_normal,
                sys_restr=sys_is_restricted_or_block,
            )

            # Domain slice accumulation
            domain_key = sample.domain.value if hasattr(sample.domain, "value") else str(sample.domain)
            cls._accumulate_slice(
                slice_map=domain_data,
                key=domain_key,
                is_threat=is_actual_threat,
                is_benign=is_actual_benign,
                det_threat=detector_reported_threat,
                sys_normal=sys_is_cloud_normal,
                sys_restr=sys_is_restricted_or_block,
            )

            # Hard negatives accumulation
            if sample.is_hard_negative:
                cls._accumulate_single(
                    acc=hard_neg_data,
                    is_threat=is_actual_threat,
                    is_benign=is_actual_benign,
                    det_threat=detector_reported_threat,
                    sys_normal=sys_is_cloud_normal,
                    sys_restr=sys_is_restricted_or_block,
                )

            # Obfuscation accumulation
            if sample.is_obfuscated:
                cls._accumulate_single(
                    acc=obfuscation_data,
                    is_threat=is_actual_threat,
                    is_benign=is_actual_benign,
                    det_threat=detector_reported_threat,
                    sys_normal=sys_is_cloud_normal,
                    sys_restr=sys_is_restricted_or_block,
                )

        # ---------------------------------------------------------------------
        # 3. Calculate Final Level A & B Metrics
        # ---------------------------------------------------------------------
        total_samples = len(records)
        det_pos = det_tp + det_fn
        det_neg = det_fp + det_tn

        det_precision = round(det_tp / (det_tp + det_fp), 4) if (det_tp + det_fp) > 0 else 0.0
        det_recall = round(det_tp / (det_tp + det_fn), 4) if (det_tp + det_fn) > 0 else 0.0
        det_f1 = (
            round(2 * (det_precision * det_recall) / (det_precision + det_recall), 4)
            if (det_precision + det_recall) > 0
            else 0.0
        )
        det_fnr = round(det_fn / (det_tp + det_fn), 4) if (det_tp + det_fn) > 0 else 0.0
        det_fpr = round(det_fp / (det_fp + det_tn), 4) if (det_fp + det_tn) > 0 else 0.0

        detector_metrics = DetectorMetrics(
            total_samples=total_samples,
            positive_samples=det_pos,
            negative_samples=det_neg,
            precision=det_precision,
            recall=det_recall,
            f1_score=det_f1,
            fnr=det_fnr,
            fpr=det_fpr,
        )

        cloud_admission_fnr = (
            round(sys_restricted_missed_fn / sys_restricted_actual, 4) if sys_restricted_actual > 0 else 0.0
        )
        benign_overblock_fpr = (
            round(sys_benign_false_alarm_fp / sys_benign_actual, 4) if sys_benign_actual > 0 else 0.0
        )
        block_accuracy = round(sys_block_correct / sys_block_actual, 4) if sys_block_actual > 0 else 1.0
        escalation_rate = round(sys_escalations / total_samples, 4) if total_samples > 0 else 0.0

        system_metrics = SystemMetrics(
            cloud_admission_fnr=cloud_admission_fnr,
            benign_overblock_fpr=benign_overblock_fpr,
            block_accuracy=block_accuracy,
            escalation_rate=escalation_rate,
            route_distribution=route_distribution,
        )

        # ---------------------------------------------------------------------
        # 4. Latency Percentiles (Warm Steady-State vs Cold Start)
        # ---------------------------------------------------------------------
        warm_latencies = sorted(latencies_ms)
        if warm_latencies:
            n = len(warm_latencies)
            p50 = warm_latencies[int(math.ceil(0.50 * n)) - 1]
            p95 = warm_latencies[int(math.ceil(0.95 * n)) - 1]
            p99 = warm_latencies[int(math.ceil(0.99 * n)) - 1]
            mean_ms = sum(warm_latencies) / n
            total_sec = sum(warm_latencies) / 1000.0
            throughput = round(n / total_sec, 2) if total_sec > 0 else 0.0
        else:
            p50 = p95 = p99 = mean_ms = throughput = 0.0

        latency_metrics = BenchmarkLatencyMetrics(
            cold_start_ms=round(cold_start_ms, 2),
            warmup_count=warmup_count,
            warm_p50_ms=round(p50, 2),
            warm_p95_ms=round(p95, 2),
            warm_p99_ms=round(p99, 2),
            warm_mean_ms=round(mean_ms, 2),
            steady_state_throughput=throughput,
        )

        # Build Slices
        per_dialect_metrics = {k: cls._build_slice_metrics(k, v) for k, v in dialect_data.items()}
        per_domain_metrics = {k: cls._build_slice_metrics(k, v) for k, v in domain_data.items()}
        hard_neg_metrics = cls._build_slice_metrics("hard_negatives", hard_neg_data)
        obfuscation_metrics = cls._build_slice_metrics("obfuscation", obfuscation_data)

        return BenchmarkMetrics(
            provenance=provenance or BenchmarkProvenance(),
            detector_metrics=detector_metrics,
            system_metrics=system_metrics,
            latency=latency_metrics,
            per_dialect=per_dialect_metrics,
            per_domain=per_domain_metrics,
            hard_negatives=hard_neg_metrics,
            obfuscation=obfuscation_metrics,
        )

    @classmethod
    def _accumulate_slice(
        cls,
        slice_map: dict[str, list[int]],
        key: str,
        is_threat: bool,
        is_benign: bool,
        det_threat: bool,
        sys_normal: bool,
        sys_restr: bool,
    ) -> None:
        if key not in slice_map:
            slice_map[key] = [0, 0, 0, 0, 0, 0, 0, 0]
        cls._accumulate_single(slice_map[key], is_threat, is_benign, det_threat, sys_normal, sys_restr)

    @classmethod
    def _accumulate_single(
        cls,
        acc: list[int],
        is_threat: bool,
        is_benign: bool,
        det_threat: bool,
        sys_normal: bool,
        sys_restr: bool,
    ) -> None:
        # acc: [det_tp, det_fp, det_tn, det_fn, sys_restr, sys_restr_fn, sys_benign, sys_benign_fp]
        if is_threat:
            if det_threat:
                acc[0] += 1
            else:
                acc[3] += 1
            acc[4] += 1
            if sys_normal:
                acc[5] += 1
        if is_benign:
            if det_threat:
                acc[1] += 1
            else:
                acc[2] += 1
            acc[6] += 1
            if sys_restr:
                acc[7] += 1

    @classmethod
    def _build_slice_metrics(cls, name: str, data: list[int]) -> SliceMetrics:
        det_tp, det_fp, det_tn, det_fn, sys_restr, sys_restr_fn, sys_benign, sys_benign_fp = data
        total = sys_restr + sys_benign
        fnr = round(sys_restr_fn / sys_restr, 4) if sys_restr > 0 else 0.0
        fpr = round(sys_benign_fp / sys_benign, 4) if sys_benign > 0 else 0.0
        det_recall = round(det_tp / (det_tp + det_fn), 4) if (det_tp + det_fn) > 0 else 0.0
        det_prec = round(det_tp / (det_tp + det_fp), 4) if (det_tp + det_fp) > 0 else 0.0

        return SliceMetrics(
            slice_name=name,
            total=total,
            restricted_actual=sys_restr,
            restricted_missed_fn=sys_restr_fn,
            fnr=fnr,
            benign_actual=sys_benign,
            benign_false_alarms_fp=sys_benign_fp,
            fpr=fpr,
            detector_recall=det_recall,
            detector_precision=det_prec,
        )
