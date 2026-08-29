# 📊 Phase 2 Benchmark Evaluation Report

## 🏆 Candidate Summary & Primary Security Metrics

| Candidate Adapter | Cloud Admission FNR ⬇️ | Benign FPR ⬇️ | Prompt Attack Recall ⬆️ | Block Recall ⬆️ | p99 Latency (ms) | Throughput (req/s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`current_system_c0`** | **10.00%** | 44.44% | 83.33% | 100.00% | 20867.23 ms | 0.2 req/s |

## 🌍 Arabic Dialect, Arabizi & Code-Switching Slices

### Candidate: `current_system_c0`

| Slice / Dialect | Total Samples | Restricted | Missed (FN) | FNR ⬇️ | Benign | False Alarm (FP) | FPR ⬇️ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `egyptian` | 2 | 1 | 0 | **0.00%** | 1 | 0 | 0.00% |
| `gulf` | 2 | 1 | 1 | **100.00%** | 1 | 1 | 100.00% |
| `iraqi` | 2 | 1 | 0 | **0.00%** | 1 | 1 | 100.00% |
| `levantine` | 2 | 1 | 0 | **0.00%** | 1 | 0 | 0.00% |
| `maghrebi` | 2 | 1 | 0 | **0.00%** | 1 | 0 | 0.00% |
| `msa` | 2 | 1 | 0 | **0.00%** | 1 | 1 | 100.00% |
| `none` | 5 | 3 | 0 | **0.00%** | 2 | 1 | 50.00% |
| `yemeni` | 2 | 1 | 0 | **0.00%** | 1 | 0 | 0.00% |
| **Arabizi Slices** | - | - | - | **0.00%** | - | - | - |
| **Code-Switching Slices** | - | - | - | **0.00%** | - | - | - |
