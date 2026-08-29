"""
Benchmark Report Generator — Two-Level Decoupled Scientific Matrix.

Generates:
1. Provenance & Reproducibility Headers (SHA-256 Dataset Hash, Git Commit, Schema Versions).
2. Level A: Standalone Detector Accuracy & Discriminative Power (Precision, Recall, F1, FNR, FPR).
3. Level B: End-to-End Gateway & Policy Performance (Cloud Admission FNR, Overblocking FPR, Escalation).
4. Latency Distribution (Cold Start vs Warm p50/p95/p99).
5. Stratified Dialect, Domain, Hard Negative, and Obfuscation Matrices.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List
from benchmark.runner import BenchmarkRunResult


class BenchmarkReportGenerator:
    """Formats benchmark results into executive and scientific summaries."""

    @classmethod
    def generate_markdown(cls, results: list[BenchmarkRunResult]) -> str:
        """Generate comprehensive markdown comparative report."""
        lines: list[str] = []
        lines.append("# 📊 Model Evaluation & Security Benchmark Report")
        lines.append("")

        if results:
            prov = results[0].metrics.provenance
            lines.append("### 🧬 Experiment Provenance & Environment")
            lines.append(f"- **Git Commit Hash**: `{prov.git_commit}`")
            lines.append(f"- **Dataset**: `{prov.dataset_name}` (v`{prov.dataset_version}`)")
            lines.append(f"- **Dataset SHA-256**: `{prov.dataset_hash_sha256}`")
            lines.append(f"- **PDP Policy Version**: `{prov.policy_version}`")
            lines.append(f"- **Execution Timestamp**: `{prov.run_timestamp}`")
            lines.append(f"- **Hardware**: `{prov.hardware_device}`")
            lines.append("")

        # ---------------------------------------------------------------------
        # Table 1: Level B - End-to-End Gateway & Routing SLA
        # ---------------------------------------------------------------------
        lines.append("## 🛡️ Level B: End-to-End Gateway Performance (SLA & Security Routes)")
        lines.append("")
        lines.append(
            "| Candidate Adapter | Cloud Admission FNR ⬇️ | Benign Overblock FPR ⬇️ | Block Accuracy ⬆️ | Escalation Rate | Warm p95 Latency | Warm Throughput |"
        )
        lines.append(
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |"
        )

        for res in results:
            m = res.metrics
            sm = m.system_metrics
            lat = m.latency
            lines.append(
                f"| **`{res.adapter_id}`** | **{sm.cloud_admission_fnr * 100:.2f}%** | {sm.benign_overblock_fpr * 100:.2f}% | "
                f"{sm.block_accuracy * 100:.2f}% | {sm.escalation_rate * 100:.2f}% | "
                f"{lat.warm_p95_ms:.2f} ms | {lat.steady_state_throughput:.1f} req/s |"
            )

        lines.append("")

        # ---------------------------------------------------------------------
        # Table 2: Level A - Standalone Detector Performance
        # ---------------------------------------------------------------------
        lines.append("## 🔬 Level A: Standalone Detector Performance (Intrinsic Accuracy)")
        lines.append("")
        lines.append(
            "| Candidate Adapter | Recall (Threats) ⬆️ | Miss Rate (FNR) ⬇️ | Precision ⬆️ | False Alarm (FPR) ⬇️ | F1-Score ⬆️ | Cold Start |"
        )
        lines.append(
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |"
        )

        for res in results:
            m = res.metrics
            dm = m.detector_metrics
            lat = m.latency
            lines.append(
                f"| **`{res.adapter_id}`** | **{dm.recall * 100:.2f}%** | {dm.fnr * 100:.2f}% | "
                f"{dm.precision * 100:.2f}% | {dm.fpr * 100:.2f}% | "
                f"**{dm.f1_score:.4f}** | {lat.cold_start_ms:.1f} ms |"
            )

        lines.append("")

        # ---------------------------------------------------------------------
        # Dialect Breakdown Matrix
        # ---------------------------------------------------------------------
        lines.append("## 🌍 Dialectal Robustness Breakdown")
        lines.append("")

        for res in results:
            m = res.metrics
            lines.append(f"### Candidate: `{res.adapter_id}`")
            lines.append("")
            lines.append(
                "| Dialect Slice | Total Samples | Restricted | Missed (FN) | System FNR ⬇️ | Benign | False Alarm (FP) | System FPR ⬇️ | Det Recall ⬆️ |"
            )
            lines.append(
                "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
            )

            for d_name, d_met in sorted(m.per_dialect.items()):
                lines.append(
                    f"| `{d_name}` | {d_met.total} | {d_met.restricted_actual} | {d_met.restricted_missed_fn} | "
                    f"**{d_met.fnr * 100:.2f}%** | {d_met.benign_actual} | {d_met.benign_false_alarms_fp} | "
                    f"{d_met.fpr * 100:.2f}% | {d_met.detector_recall * 100:.2f}% |"
                )

            lines.append("")

        # ---------------------------------------------------------------------
        # Domain Breakdown Matrix
        # ---------------------------------------------------------------------
        lines.append("## 📚 Semantic & Domain Breakdown")
        lines.append("")

        for res in results:
            m = res.metrics
            lines.append(f"### Candidate: `{res.adapter_id}` (Domains)")
            lines.append("")
            lines.append(
                "| Domain Slice | Total Samples | Restricted | Missed (FN) | System FNR ⬇️ | Benign | False Alarm (FP) | System FPR ⬇️ |"
            )
            lines.append(
                "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
            )

            for dom_name, dom_met in sorted(m.per_domain.items()):
                lines.append(
                    f"| `{dom_name}` | {dom_met.total} | {dom_met.restricted_actual} | {dom_met.restricted_missed_fn} | "
                    f"**{dom_met.fnr * 100:.2f}%** | {dom_met.benign_actual} | {dom_met.benign_false_alarms_fp} | "
                    f"{dom_met.fpr * 100:.2f}% |"
                )

            # Special Stress slices
            hn = m.hard_negatives
            obf = m.obfuscation
            lines.append(
                f"| **`[Stress] Hard Negatives`** | {hn.total} | {hn.restricted_actual} | {hn.restricted_missed_fn} | "
                f"**{hn.fnr * 100:.2f}%** | {hn.benign_actual} | {hn.benign_false_alarms_fp} | {hn.fpr * 100:.2f}% |"
            )
            lines.append(
                f"| **`[Stress] Obfuscated Attacks`** | {obf.total} | {obf.restricted_actual} | {obf.restricted_missed_fn} | "
                f"**{obf.fnr * 100:.2f}%** | {obf.benign_actual} | {obf.benign_false_alarms_fp} | {obf.fpr * 100:.2f}% |"
            )
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def save_json(cls, result: BenchmarkRunResult, output_path: Path | str) -> None:
        """Save benchmark run result to JSON."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.model_dump(), f, indent=2, ensure_ascii=False)
