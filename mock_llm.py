"""
Mock Local LLM Server & Mock Cloud Backend with Call Counter.

Provides lightweight, standalone test servers for end-to-end integration and fail-safe proofs:
- Port 8100: Mock Local LLM (OpenAI-compatible /v1/chat/completions)
- Port 9000: Mock Cloud Backend with strict invocation counter (/count)
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock_llm")

# ============================================================================
# 1. Mock Local LLM (Port 8100)
# ============================================================================

local_app = FastAPI(title="Mock Local LLM")


@local_app.post("/v1/chat/completions")
async def local_chat_completions(request: Request) -> JSONResponse:
    data = await request.json()
    messages = data.get("messages", [])
    prompt_str = " ".join(str(m.get("content", "")) for m in messages)

    logger.info("[Mock Local LLM] Received request: %s", prompt_str[:60])

    # Dynamic controllable responses for testing Local Judge
    if "force_private_key" in prompt_str:
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    elif "force_ssn" in prompt_str or "account details" in prompt_str.lower():
        content = "User verification successful. SSN: 123-45-6789, Card: 4000-0000-0000-0002."
    else:
        content = f"Mock local response to: '{prompt_str[:40]}...'"

    return JSONResponse(
        content={
            "id": "chatcmpl-mock-local",
            "object": "chat.completion",
            "model": "mock-local-model",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        }
    )


@local_app.get("/health")
async def local_health() -> JSONResponse:
    return JSONResponse(content={"status": "healthy", "service": "mock-local-llm"})


# ============================================================================
# 2. Mock Cloud Backend with Call Counter (Port 9000)
# ============================================================================

cloud_app = FastAPI(title="Mock Cloud Backend")
cloud_counter_lock = threading.Lock()
cloud_call_count = 0


@cloud_app.get("/count")
async def get_cloud_count() -> JSONResponse:
    with cloud_counter_lock:
        return JSONResponse(content={"cloud_call_count": cloud_call_count})


@cloud_app.post("/count/reset")
async def reset_cloud_count() -> JSONResponse:
    global cloud_call_count
    with cloud_counter_lock:
        cloud_call_count = 0
        return JSONResponse(content={"cloud_call_count": 0, "status": "reset"})


@cloud_app.post("/v1/chat/completions")
async def cloud_chat_completions(request: Request) -> JSONResponse:
    global cloud_call_count
    with cloud_counter_lock:
        cloud_call_count += 1
        current_count = cloud_call_count

    data = await request.json()
    messages = data.get("messages", [])
    prompt_str = " ".join(str(m.get("content", "")) for m in messages)

    logger.warning("[Mock Cloud Backend] INVOCATION #%d: '%s'", current_count, prompt_str[:60])

    return JSONResponse(
        content={
            "id": "chatcmpl-mock-cloud",
            "object": "chat.completion",
            "model": "mock-cloud-model",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Cloud response from mock backend."},
                    "finish_reason": "stop",
                }
            ],
        }
    )


def run_all(local_port: int = 8100, cloud_port: int = 9000):
    """Run both mock servers in concurrent threads."""
    def run_local():
        uvicorn.run(local_app, host="127.0.0.1", port=local_port, log_level="warning")

    def run_cloud():
        uvicorn.run(cloud_app, host="127.0.0.1", port=cloud_port, log_level="warning")

    t1 = threading.Thread(target=run_local, daemon=True)
    t2 = threading.Thread(target=run_cloud, daemon=True)
    t1.start()
    t2.start()
    logger.info("Mock Local LLM running at http://127.0.0.1:%d", local_port)
    logger.info("Mock Cloud Backend running at http://127.0.0.1:%d", cloud_port)
    return t1, t2


if __name__ == "__main__":
    t1, t2 = run_all()
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping mock servers...")
