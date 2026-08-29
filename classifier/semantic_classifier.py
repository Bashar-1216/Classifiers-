"""
Clean Local Semantic Risk Classifier & Evidence Generator.

Operates 100% locally on CPU without any cloud or network egress:
1. Fast Word & Morphological Root Similarity against Latent Threat Centroids
2. Decoupled Neural Guard Support (via GuardOrchestrator)
3. Shannon Entropy Anomaly Detection (Statistical Obfuscation)
4. Continuous Evidence & Uncertainty Output for Declarative Policy Evaluation
"""

from __future__ import annotations

import json
import logging
import math
import re
from pathlib import Path
from typing import Any, Optional

from classifier.guard_models import GuardEvidence, GuardMode, GuardVerdict
from classifier.guard_orchestrator import GuardOrchestrator

logger = logging.getLogger(__name__)

import os
DEFAULT_KNOWLEDGE_PATH = Path(__file__).parent.parent / "knowledge" / "risk_knowledge.json"
DEFAULT_GUARD_MODEL_ID = os.getenv(
    "LLAMA_GUARD_MODEL_PATH",
    "E:/models/Llama-Guard-3-1B" if Path("E:/models/Llama-Guard-3-1B").exists() else "meta-llama/Llama-Guard-3-1B",
)


class SemanticClassifier:
    """
    High-Precision Local AI Semantic Classifier & Neural Guard Engine.
    Guarantees 100% offline, local-only CPU execution (Zero Cloud Ingress).
    """

    TAXONOMY_MAP = {
        "S1": "violent_crimes",
        "S2": "non_violent_crimes",
        "S3": "sex_crimes",
        "S4": "child_exploitation",
        "S5": "defamation",
        "S6": "specialized_advice",
        "S7": "privacy",
        "S8": "intellectual_property",
        "S9": "indiscriminate_weapons",
        "S10": "hate_speech",
        "S11": "suicide_self_harm",
        "S12": "sexual_content",
        "S13": "elections",
        "S14": "code_interpreter_abuse",
    }

    def __init__(
        self,
        knowledge_file: Path | str | None = None,
        min_similarity_threshold: float = 0.24,
        onnx_model_path: str | None = None,
        guard_model_path: str | None = None,
        enable_neural_guard: bool = True,
        guard_mode: GuardMode = GuardMode.SHADOW,
    ) -> None:
        self.knowledge_file = Path(knowledge_file) if knowledge_file else DEFAULT_KNOWLEDGE_PATH
        self.min_similarity_threshold = min_similarity_threshold
        self.onnx_model_path = onnx_model_path
        self.guard_model_path = guard_model_path or DEFAULT_GUARD_MODEL_ID
        self.enable_neural_guard = enable_neural_guard
        self._onnx_session = None
        self._neural_model = None
        self._neural_tokenizer = None
        self._neural_model_loaded = False
        self.guard_orchestrator = GuardOrchestrator(mode=guard_mode)

        self.clusters: dict[str, list[str]] = {}
        self._cluster_word_sets: dict[str, set[str]] = {}

        # 1. Load External Dynamic Risk Knowledge Base
        self.load_knowledge_base()

        # 2. Optional Local ONNX Neural Session
        if onnx_model_path and Path(onnx_model_path).exists():
            try:
                import onnxruntime as ort
                self._onnx_session = ort.InferenceSession(
                    onnx_model_path,
                    providers=["CPUExecutionProvider"],
                )
                logger.info("ONNX Transformer Neural Session initialized from %s", onnx_model_path)
            except Exception as e:
                logger.warning("Could not initialize local ONNX model: %s", e)

        logger.info(
            "Local SemanticClassifier initialized across %d semantic knowledge clusters.",
            len(self.clusters),
        )

    def _load_neural_guard(self) -> bool:
        """Lazy load Llama-Guard-3-1B model and tokenizer into process memory if local path exists."""
        if self._neural_model_loaded:
            return self._neural_model is not None

        if not self.enable_neural_guard or not self.guard_model_path:
            return False

        if not Path(self.guard_model_path).exists():
            # Zero external network ingress during offline CPU execution
            self._neural_model_loaded = True
            return False

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            logger.info("Initializing Local Llama-Guard-3-1B runtime (%s)...", self.guard_model_path)
            self._neural_tokenizer = AutoTokenizer.from_pretrained(self.guard_model_path, local_files_only=True)
            self._neural_model = AutoModelForCausalLM.from_pretrained(
                self.guard_model_path,
                local_files_only=True,
                torch_dtype=torch.float32,
                low_cpu_mem_usage=True,
            )
            self._neural_model.eval()
            self._neural_model_loaded = True
            logger.info("Local Llama-Guard-3-1B model successfully loaded into memory!")
            return True
        except Exception as exc:
            self._neural_model_loaded = True
            self._neural_model = None
            self._neural_tokenizer = None
            logger.warning("Local Llama-Guard-3-1B could not be loaded into memory (%s). Fallback to fast centroids.", exc)
            return False

    def evaluate_neural_guard(self, text: str) -> dict[str, float]:
        """
        Run forward inference with Llama-Guard-3-1B locally on CPU.
        """
        if not self._load_neural_guard() or self._neural_model is None or self._neural_tokenizer is None:
            return {}

        try:
            import torch

            # Standard Llama-Guard-3 Prompt Template
            formatted_prompt = (
                f"<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n"
                f"{text}\n<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
            )

            inputs = self._neural_tokenizer(formatted_prompt, return_tensors="pt")

            with torch.no_grad():
                output_ids = self._neural_model.generate(
                    **inputs,
                    max_new_tokens=20,
                    pad_token_id=self._neural_tokenizer.eos_token_id,
                    do_sample=False,
                )

            generated_tokens = output_ids[0][inputs["input_ids"].shape[1] :]
            raw_output = self._neural_tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()

            scores: dict[str, float] = {}

            # Parse safe / unsafe verdict
            first_line = raw_output.split("\n")[0].strip().lower()
            if "unsafe" in first_line:
                # Extract S1..S14 codes
                codes = re.findall(r"\bS([1-9]|1[0-4])\b", raw_output, re.IGNORECASE)
                if codes:
                    for code_num in codes:
                        code_tag = f"S{code_num}"
                        category = self.TAXONOMY_MAP.get(code_tag, "general_safety")
                        scores[category] = 0.95
                        scores[f"guard_{code_tag.lower()}"] = 0.95
                else:
                    scores["general_safety"] = 0.90
                    scores["guard_unsafe"] = 0.90

            return scores

        except Exception as exc:
            logger.error("Error during local neural guard inference: %s", exc)
            return {}

    def load_knowledge_base(self) -> None:
        """Load external semantic risk knowledge clusters from SecurityKnowledgeBundle."""
        try:
            from security_knowledge.loader import KnowledgeLoader
            bundle = KnowledgeLoader.get_bundle()
            if bundle.semantic_anchors:
                self.clusters = bundle.semantic_anchors
                self._compile_cluster_words()
                return
        except Exception as exc:
            logger.warning("Could not load bundle semantic anchors: %s", exc)

        if self.knowledge_file.exists():
            try:
                with open(self.knowledge_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.clusters = data.get("semantic_clusters", data.get("clusters", {}))
                    self._compile_cluster_words()
                    return
            except Exception as exc:
                logger.warning("Failed to load knowledge file %s: %s", self.knowledge_file, exc)

    def _compile_cluster_words(self) -> None:
        """Pre-tokenize cluster anchors for sub-millisecond similarity scoring."""
        self._cluster_word_sets = {}
        for tag, anchors in self.clusters.items():
            words: set[str] = set()
            for a in anchors:
                words.update(re.findall(r"\w+", a.lower()))
            self._cluster_word_sets[tag] = words

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon Information Entropy for obfuscation and anomaly detection."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def classify_intent(self, text: str) -> dict[str, float]:
        """
        Classify text intent across risk categories using neural inference + morphological overlap + entropy.
        """
        if not text or not text.strip():
            return {}

        scores: dict[str, float] = {}

        # 1. Neural Guard Llama-Guard-3-1B Local Forward Pass (if available)
        neural_scores = self.evaluate_neural_guard(text)
        if neural_scores:
            scores.update(neural_scores)

        text_lower = text.lower()
        tokens = set(re.findall(r"\w+", text_lower))
        if not tokens:
            return scores

        # 2. Morphological Token Overlap Scoring (Centroids)
        for tag, cluster_words in self._cluster_word_sets.items():
            if not cluster_words:
                continue
            intersection = tokens.intersection(cluster_words)
            if intersection:
                overlap_ratio = len(intersection) / min(len(tokens), len(cluster_words))
                if overlap_ratio >= self.min_similarity_threshold:
                    scores[tag] = max(scores.get(tag, 0.0), round(min(0.95, overlap_ratio * 1.5), 4))

        # 3. Shannon Entropy Obfuscation Signal
        entropy = self.calculate_entropy(text)
        if entropy > 4.5 and len(text) > 40:
            scores["statistical_high_entropy_obfuscation"] = max(
                scores.get("statistical_high_entropy_obfuscation", 0.0),
                round(min(0.90, (entropy - 4.5) / 2.0 + 0.5), 4),
            )

        return scores

    def evaluate(self, text: str) -> dict[str, float]:
        """Pipeline evaluation interface matching ClassifierService contract."""
        return self.classify_intent(text)
