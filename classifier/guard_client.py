"""
Resilient Async Client for Local Guard Inference Service.
Enforces strict timeouts, connection resilience, and Fail-Closed guarantees.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional
import httpx

from classifier.guard_models import GuardEvidence, GuardVerdict
from classifier.guard_parser import GuardOutputParser

logger = logging.getLogger(__name__)

DEFAULT_GUARD_SERVICE_URL = "http://localhost:8002"
DEFAULT_TIMEOUT_SECONDS = 2.0


class GuardServiceClient:
    """
    Asynchronous client communicating with the isolated Local Guard Microservice.
    Guarantees Fail-Closed fallback on timeout or service unavailability.
    """

    def __init__(
        self,
        service_url: str = DEFAULT_GUARD_SERVICE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        taxonomy_mapping: Optional[Dict[str, str]] = None,
    ) -> None:
        self.service_url = service_url.rstrip("/")
        self.timeout = timeout
        self.parser = GuardOutputParser(taxonomy_mapping)
        self.client = httpx.AsyncClient(timeout=timeout)

    async def evaluate(
        self,
        prompt: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GuardEvidence:
        """
        Send evaluation request to Local Guard Microservice.
        On any network error or timeout, returns GuardVerdict.UNAVAILABLE.
        """
        t0 = time.perf_counter()
        endpoint = f"{self.service_url}/v1/evaluate"
        payload = {"prompt": prompt, "metadata": metadata or {}}

        try:
            resp = await self.client.post(endpoint, json=payload)
            latency_ms = (time.perf_counter() - t0) * 1000

            if resp.status_code == 200:
                data = resp.json()
                raw_text = data.get("verdict_text", "")
                model_id = data.get("model_id", "local-guard")
                model_rev = data.get("model_revision", "v1")

                verdict, raw_cats, canonical_cats = self.parser.parse(raw_text)
                return GuardEvidence(
                    verdict=verdict,
                    raw_output=raw_text,
                    raw_categories=raw_cats,
                    canonical_categories=canonical_cats,
                    confidence=data.get("confidence", 1.0),
                    latency_ms=latency_ms,
                    model_id=model_id,
                    model_revision=model_rev,
                    status="ok",
                )
            else:
                logger.warning("Guard service returned HTTP %d: %s", resp.status_code, resp.text)
                return GuardEvidence(
                    verdict=GuardVerdict.ERROR,
                    raw_output=resp.text,
                    latency_ms=latency_ms,
                    status=f"http_error_{resp.status_code}",
                )

        except (httpx.TimeoutException, httpx.NetworkError, Exception) as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            logger.warning("Guard service connection failed (%s): %s", type(exc).__name__, exc)
            # Fail-Closed signal: Guard is unavailable
            return GuardEvidence(
                verdict=GuardVerdict.UNAVAILABLE,
                raw_output=str(exc),
                latency_ms=latency_ms,
                status="service_unavailable",
            )

    async def check_health(self) -> bool:
        """Check if Guard microservice is live and ready."""
        try:
            resp = await self.client.get(f"{self.service_url}/health", timeout=1.0)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self.client.aclose()
