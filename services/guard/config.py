"""
Configuration for Local Guard Microservice.
"""

from __future__ import annotations
import os
from pydantic import BaseModel


class GuardServiceConfig(BaseModel):
    host: str = os.getenv("GUARD_SERVICE_HOST", "0.0.0.0")
    port: int = int(os.getenv("GUARD_SERVICE_PORT", "8002"))
    model_id: str = os.getenv("GUARD_MODEL_ID", "meta-llama/Llama-Guard-3-1B")
    device: str = os.getenv("GUARD_DEVICE", "cuda")
    torch_dtype: str = os.getenv("GUARD_DTYPE", "float16")
    max_new_tokens: int = int(os.getenv("GUARD_MAX_NEW_TOKENS", "25"))
    batch_size: int = int(os.getenv("GUARD_BATCH_SIZE", "32"))
    workers: int = 1
