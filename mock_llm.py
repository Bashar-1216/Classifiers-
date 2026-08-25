"""
Mock Local LLM Server — OpenAI Compatible.

A lightweight mock server for local testing without requiring a GPU or real vLLM instance.
Listens on port 8100 (or configured port) and returns OpenAI-compatible chat completion responses.
"""

from __future__ import annotations

import argparse
import time
import uuid

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Mock Local LLM Server", version="1.0.0")


class Message(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "meta-llama/Meta-Llama-3-8B-Instruct"
    messages: list[Message]
    temperature: float = 0.7
    max_tokens: int = 512


@app.get("/health")
async def health():
    return {"status": "healthy", "model": "mock-local-llm"}


@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def chat_completions(req: ChatCompletionRequest):
    last_user_msg = ""
    for m in reversed(req.messages):
        if m.role == "user":
            last_user_msg = m.content
            break

    # Generate a realistic mock response based on prompt
    response_content = (
        f"[Local LLM response ({req.model})]: Processed securely inside isolated Shield environment. "
        f"Input query was: '{last_user_msg[:60]}...'"
    )

    return {
        "id": f"chatcmpl-mock-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_content,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": len(last_user_msg.split()),
            "completion_tokens": len(response_content.split()),
            "total_tokens": len(last_user_msg.split()) + len(response_content.split()),
        },
    }


def run(host: str = "127.0.0.1", port: int = 8100):
    print(f"🚀 Starting Mock Local LLM on http://{host}:{port}...")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Mock Local LLM Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8100, help="Bind port")
    args = parser.parse_args()
    run(args.host, args.port)
