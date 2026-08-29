"""
DeBERTa-v3 Prompt Injection Guard Adapter (Candidate Model #2).

Evaluates DeBERTa-v3-Base Prompt Injection model as a standalone detector
for prompt injection, jailbreak attempts, and adversarial overrides.
"""

from __future__ import annotations

import time
import hashlib
from pathlib import Path
from typing import Any
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from benchmark.adapters.base import BaseDetectorAdapter
from benchmark.schema import BenchmarkSample
from classifier.evidence_models import (
    ConfidenceBand,
    DetectionSignal,
    PromptAttackEvidence,
    ScoreType,
    SecurityEvidence,
)


class DebertaGuardAdapter(BaseDetectorAdapter):
    """Candidate detector adapter powered by DeBERTa-v3."""

    def __init__(
        self,
        model_path: str = "E:/models/deberta-v3-prompt-injection",
        device: str = "cpu",
    ) -> None:
        super().__init__(adapter_id="deberta_v3_guard", adapter_version="1.0.0")
        self.device = device
        self.model_path = Path(model_path)
        
        self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(self.model_path))
        self.model.eval()
        if device != "cpu" and torch.cuda.is_available():
            self.model.to(device)

    def detect(self, sample: BenchmarkSample) -> SecurityEvidence:
        t0 = time.perf_counter()
        
        inputs = self.tokenizer(
            sample.text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        )
        if self.device != "cpu" and torch.cuda.is_available():
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
        with torch.no_grad():
            logits = self.model(**inputs).logits
            probs = torch.softmax(logits, dim=-1).squeeze().tolist()
            
        # Label 0: SAFE, Label 1: INJECTION
        safe_prob = float(probs[0])
        injection_prob = float(probs[1])
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        
        is_attack = injection_prob >= 0.50
        band = ConfidenceBand.CLEAR_HIGH if is_attack else ConfidenceBand.CLEAR_LOW

        signal = DetectionSignal(
            detector_id="deberta_v3_guard",
            detector_version="1.0.0",
            raw_score=injection_prob,
            score_type=ScoreType.PROBABILITY,
            calibrated_probability=injection_prob,
            calibration_version="deberta_cal_v1",
            confidence_band=band,
            applicable=True,
            latency_ms=elapsed_ms,
            reason_codes=["deberta_injection_detected"] if is_attack else ["deberta_safe"],
        )

        prompt_attack = PromptAttackEvidence(
            direct_injection=signal if is_attack else DetectionSignal(detector_id="prompt_attack.direct_injection"),
            jailbreak=signal if is_attack else DetectionSignal(detector_id="prompt_attack.jailbreak"),
            role_override=signal if is_attack else DetectionSignal(detector_id="prompt_attack.role_override"),
        )

        prompt_hash = hashlib.sha256(sample.text.encode("utf-8")).hexdigest()

        return SecurityEvidence(
            canonical_text=sample.text,
            raw_prompt_hash=prompt_hash,
            prompt_attack=prompt_attack,
        )
