"""
Model Inference Backend for Guard Microservice.
Encapsulates Hugging Face / PyTorch runtime and template formatting.
"""

from __future__ import annotations

import logging
import time
from typing import Optional
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from services.guard.config import GuardServiceConfig

logger = logging.getLogger(__name__)

LLAMA_GUARD_TEMPLATE = """<|begin_of_text|><|start_header_id|>user<|end_header_id|>

Task: Check if there is unsafe content in 'User' messages in conversations according to our safety policy with the below categories.

<BEGIN UNSAFE CONTENT CATEGORIES>
S1: Violent Crimes.
S2: Non-Violent Crimes.
S3: Sex-Related Crimes.
S4: Child Sexual Exploitation.
S5: Defamation.
S6: Specialized Advice.
S7: Privacy.
S8: Intellectual Property.
S9: Indiscriminate Weapons.
S10: Hate.
S11: Suicide & Self-Harm.
S12: Sexual Content.
S13: Elections.
S14: Code Interpreter Abuse.
<END UNSAFE CONTENT CATEGORIES>

<BEGIN CONVERSATION>

User: {prompt}

<END CONVERSATION>

Provide your safety assessment for ONLY THE LAST User message in the above conversation:
- First line must read 'safe' or 'unsafe'.
- If unsafe, a second line must include a comma-separated list of violated categories.<|eot_id|><|start_header_id|>assistant<|end_header_id|>

"""


class GuardInferenceBackend:
    """
    Manages model loading and GPU/CPU inference inside the decoupled microservice.
    """

    def __init__(self, config: GuardServiceConfig) -> None:
        self.config = config
        self.device = "cuda" if (config.device == "cuda" and torch.cuda.is_available()) else "cpu"
        self.tokenizer = None
        self.model = None
        self.is_ready = False

    def load_model(self) -> None:
        logger.info("Initializing Guard Model %s on %s...", self.config.model_id, self.device)
        self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_id)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.tokenizer.padding_side = "left"

        dtype = torch.float16 if self.device == "cuda" else torch.float32
        self.model = AutoModelForCausalLM.from_pretrained(
            self.config.model_id,
            torch_dtype=dtype,
            device_map="auto" if self.device == "cuda" else None,
        )
        self.model.eval()
        self.is_ready = True
        logger.info("Guard Model %s successfully loaded on %s.", self.config.model_id, self.device)

    def evaluate_prompt(self, prompt_text: str) -> tuple[str, float]:
        """Execute single-prompt inference."""
        if not self.is_ready:
            raise RuntimeError("Guard model is not initialized")

        formatted = LLAMA_GUARD_TEMPLATE.format(prompt=prompt_text)
        t0 = time.perf_counter()

        inputs = self.tokenizer(formatted, return_tensors="pt").to(self.device)
        input_len = inputs.input_ids.shape[1]

        with torch.inference_mode():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=self.config.max_new_tokens,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
                do_sample=False,
            )

        generated_tokens = outputs[0][input_len:]
        decoded = self.tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()
        latency_ms = (time.perf_counter() - t0) * 1000

        return decoded, latency_ms
