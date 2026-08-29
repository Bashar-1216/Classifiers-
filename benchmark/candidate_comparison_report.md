# 📊 Model Evaluation & Security Benchmark Report

### 🧬 Experiment Provenance & Environment
- **Git Commit Hash**: `88a88a215be91d27bd1a6d7ff38a55785e2523fa`
- **Dataset**: `dialects_gold_v1` (v`1.0.0`)
- **Dataset SHA-256**: `59f09570a6c95e407533c4b0d887622192b74202c9b8bdead96e2edfe49e5d5f`
- **PDP Policy Version**: `1.1.0`
- **Execution Timestamp**: `2026-08-29T07:00:51.051128+00:00`
- **Hardware**: `CPU`

## 🛡️ Level B: End-to-End Gateway Performance (SLA & Security Routes)

| Candidate Adapter | Cloud Admission FNR ⬇️ | Benign Overblock FPR ⬇️ | Block Accuracy ⬆️ | Escalation Rate | Warm p95 Latency | Warm Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`current_system_c0`** | **15.79%** | 21.74% | 50.00% | 0.00% | 8134.51 ms | 0.2 req/s |
| **`qwen2.5_guard_0.5b`** | **10.53%** | 60.87% | 0.00% | 0.00% | 2634.81 ms | 0.5 req/s |
| **`deberta_v3_guard`** | **89.47%** | 0.00% | 0.00% | 0.00% | 299.05 ms | 4.0 req/s |

## 🔬 Level A: Standalone Detector Performance (Intrinsic Accuracy)

| Candidate Adapter | Recall (Threats) ⬆️ | Miss Rate (FNR) ⬇️ | Precision ⬆️ | False Alarm (FPR) ⬇️ | F1-Score ⬆️ | Cold Start |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`current_system_c0`** | **84.21%** | 15.79% | 76.19% | 21.74% | **0.8000** | 100788.9 ms |
| **`qwen2.5_guard_0.5b`** | **89.47%** | 10.53% | 54.84% | 60.87% | **0.6800** | 1476.0 ms |
| **`deberta_v3_guard`** | **10.53%** | 89.47% | 100.00% | 0.00% | **0.1905** | 2870.1 ms |

## 🌍 Dialectal Robustness Breakdown

### Candidate: `current_system_c0`

| Dialect Slice | Total Samples | Restricted | Missed (FN) | System FNR ⬇️ | Benign | False Alarm (FP) | System FPR ⬇️ | Det Recall ⬆️ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `egyptian` | 6 | 2 | 0 | **0.00%** | 4 | 1 | 25.00% | 100.00% |
| `gulf` | 5 | 2 | 0 | **0.00%** | 3 | 1 | 33.33% | 100.00% |
| `iraqi` | 4 | 2 | 0 | **0.00%** | 2 | 0 | 0.00% | 100.00% |
| `levantine` | 6 | 3 | 1 | **33.33%** | 3 | 0 | 0.00% | 66.67% |
| `maghrebi` | 4 | 2 | 1 | **50.00%** | 2 | 0 | 0.00% | 50.00% |
| `msa` | 6 | 3 | 0 | **0.00%** | 3 | 2 | 66.67% | 100.00% |
| `none` | 3 | 2 | 0 | **0.00%** | 1 | 1 | 100.00% | 100.00% |
| `sudanese` | 3 | 1 | 0 | **0.00%** | 2 | 0 | 0.00% | 100.00% |
| `yemeni` | 5 | 2 | 1 | **50.00%** | 3 | 0 | 0.00% | 50.00% |

### Candidate: `qwen2.5_guard_0.5b`

| Dialect Slice | Total Samples | Restricted | Missed (FN) | System FNR ⬇️ | Benign | False Alarm (FP) | System FPR ⬇️ | Det Recall ⬆️ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `egyptian` | 6 | 2 | 0 | **0.00%** | 4 | 3 | 75.00% | 100.00% |
| `gulf` | 5 | 2 | 0 | **0.00%** | 3 | 2 | 66.67% | 100.00% |
| `iraqi` | 4 | 2 | 0 | **0.00%** | 2 | 1 | 50.00% | 100.00% |
| `levantine` | 6 | 3 | 0 | **0.00%** | 3 | 3 | 100.00% | 100.00% |
| `maghrebi` | 4 | 2 | 0 | **0.00%** | 2 | 1 | 50.00% | 100.00% |
| `msa` | 6 | 3 | 1 | **33.33%** | 3 | 0 | 0.00% | 66.67% |
| `none` | 3 | 2 | 1 | **50.00%** | 1 | 0 | 0.00% | 50.00% |
| `sudanese` | 3 | 1 | 0 | **0.00%** | 2 | 2 | 100.00% | 100.00% |
| `yemeni` | 5 | 2 | 0 | **0.00%** | 3 | 2 | 66.67% | 100.00% |

### Candidate: `deberta_v3_guard`

| Dialect Slice | Total Samples | Restricted | Missed (FN) | System FNR ⬇️ | Benign | False Alarm (FP) | System FPR ⬇️ | Det Recall ⬆️ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `egyptian` | 6 | 2 | 2 | **100.00%** | 4 | 0 | 0.00% | 0.00% |
| `gulf` | 5 | 2 | 2 | **100.00%** | 3 | 0 | 0.00% | 0.00% |
| `iraqi` | 4 | 2 | 2 | **100.00%** | 2 | 0 | 0.00% | 0.00% |
| `levantine` | 6 | 3 | 3 | **100.00%** | 3 | 0 | 0.00% | 0.00% |
| `maghrebi` | 4 | 2 | 2 | **100.00%** | 2 | 0 | 0.00% | 0.00% |
| `msa` | 6 | 3 | 3 | **100.00%** | 3 | 0 | 0.00% | 0.00% |
| `none` | 3 | 2 | 0 | **0.00%** | 1 | 0 | 0.00% | 100.00% |
| `sudanese` | 3 | 1 | 1 | **100.00%** | 2 | 0 | 0.00% | 0.00% |
| `yemeni` | 5 | 2 | 2 | **100.00%** | 3 | 0 | 0.00% | 0.00% |

## 📚 Semantic & Domain Breakdown

### Candidate: `current_system_c0` (Domains)

| Domain Slice | Total Samples | Restricted | Missed (FN) | System FNR ⬇️ | Benign | False Alarm (FP) | System FPR ⬇️ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `cybersecurity` | 15 | 10 | 2 | **20.00%** | 5 | 4 | 80.00% |
| `education` | 5 | 0 | 0 | **0.00%** | 5 | 0 | 0.00% |
| `finance_banking` | 3 | 0 | 0 | **0.00%** | 3 | 0 | 0.00% |
| `fraud_social_eng` | 4 | 4 | 1 | **25.00%** | 0 | 0 | 0.00% |
| `general` | 2 | 0 | 0 | **0.00%** | 2 | 0 | 0.00% |
| `medicine_health` | 4 | 0 | 0 | **0.00%** | 4 | 1 | 25.00% |
| `privacy_secrets` | 5 | 5 | 0 | **0.00%** | 0 | 0 | 0.00% |
| `travel_daily` | 2 | 0 | 0 | **0.00%** | 2 | 0 | 0.00% |
| `workplace` | 2 | 0 | 0 | **0.00%** | 2 | 0 | 0.00% |
| **`[Stress] Hard Negatives`** | 6 | 0 | 0 | **0.00%** | 6 | 4 | 66.67% |
| **`[Stress] Obfuscated Attacks`** | 0 | 0 | 0 | **0.00%** | 0 | 0 | 0.00% |

### Candidate: `qwen2.5_guard_0.5b` (Domains)

| Domain Slice | Total Samples | Restricted | Missed (FN) | System FNR ⬇️ | Benign | False Alarm (FP) | System FPR ⬇️ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `cybersecurity` | 15 | 10 | 0 | **0.00%** | 5 | 3 | 60.00% |
| `education` | 5 | 0 | 0 | **0.00%** | 5 | 3 | 60.00% |
| `finance_banking` | 3 | 0 | 0 | **0.00%** | 3 | 2 | 66.67% |
| `fraud_social_eng` | 4 | 4 | 0 | **0.00%** | 0 | 0 | 0.00% |
| `general` | 2 | 0 | 0 | **0.00%** | 2 | 1 | 50.00% |
| `medicine_health` | 4 | 0 | 0 | **0.00%** | 4 | 2 | 50.00% |
| `privacy_secrets` | 5 | 5 | 2 | **40.00%** | 0 | 0 | 0.00% |
| `travel_daily` | 2 | 0 | 0 | **0.00%** | 2 | 1 | 50.00% |
| `workplace` | 2 | 0 | 0 | **0.00%** | 2 | 2 | 100.00% |
| **`[Stress] Hard Negatives`** | 6 | 0 | 0 | **0.00%** | 6 | 4 | 66.67% |
| **`[Stress] Obfuscated Attacks`** | 0 | 0 | 0 | **0.00%** | 0 | 0 | 0.00% |

### Candidate: `deberta_v3_guard` (Domains)

| Domain Slice | Total Samples | Restricted | Missed (FN) | System FNR ⬇️ | Benign | False Alarm (FP) | System FPR ⬇️ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `cybersecurity` | 15 | 10 | 9 | **90.00%** | 5 | 0 | 0.00% |
| `education` | 5 | 0 | 0 | **0.00%** | 5 | 0 | 0.00% |
| `finance_banking` | 3 | 0 | 0 | **0.00%** | 3 | 0 | 0.00% |
| `fraud_social_eng` | 4 | 4 | 4 | **100.00%** | 0 | 0 | 0.00% |
| `general` | 2 | 0 | 0 | **0.00%** | 2 | 0 | 0.00% |
| `medicine_health` | 4 | 0 | 0 | **0.00%** | 4 | 0 | 0.00% |
| `privacy_secrets` | 5 | 5 | 4 | **80.00%** | 0 | 0 | 0.00% |
| `travel_daily` | 2 | 0 | 0 | **0.00%** | 2 | 0 | 0.00% |
| `workplace` | 2 | 0 | 0 | **0.00%** | 2 | 0 | 0.00% |
| **`[Stress] Hard Negatives`** | 6 | 0 | 0 | **0.00%** | 6 | 0 | 0.00% |
| **`[Stress] Obfuscated Attacks`** | 0 | 0 | 0 | **0.00%** | 0 | 0 | 0.00% |
