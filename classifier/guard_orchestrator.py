"""
Guard Mode Orchestrator (Disabled / Shadow / Enforce).
Governs safe zero-downtime transition and ablation logging.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from classifier.guard_models import GuardEvidence, GuardMode, GuardVerdict
from classifier.guard_client import GuardServiceClient

logger = logging.getLogger(__name__)


class GuardOrchestrator:
    """
    Manages Guard execution modes:
    - DISABLED: Guard is bypassed (0 network calls).
    - SHADOW: Guard evaluates in background, logs telemetry for ablation comparison,
              but does not alter the authoritative pipeline decision.
    - ENFORCE: Guard evidence actively influences the RiskAggregator and PolicyEngine.
    """

    def __init__(
        self,
        mode: GuardMode = GuardMode.SHADOW,
        client: Optional[GuardServiceClient] = None,
    ) -> None:
        self.mode = mode
        self.client = client or GuardServiceClient()

    async def evaluate_shadow(
        self,
        prompt: str,
        baseline_result: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[GuardEvidence]:
        """
        Execute Guard in Shadow Mode: compare with baseline and record divergence.
        """
        if self.mode == GuardMode.DISABLED:
            return None

        evidence = await self.client.evaluate(prompt, metadata)

        if self.mode == GuardMode.SHADOW:
            # Telemetry comparison logging
            baseline_decision = getattr(baseline_result, "classification", None)
            if evidence.is_available and baseline_decision:
                base_is_restricted = (baseline_decision.value == "RESTRICTED")
                guard_is_restricted = evidence.is_unsafe
                if base_is_restricted != guard_is_restricted:
                    logger.info(
                        "[SHADOW DIVERGENCE] Baseline: %s | Guard: %s (Latency: %.1fms) | Categories: %s",
                        baseline_decision.value,
                        evidence.verdict.value,
                        evidence.latency_ms,
                        evidence.canonical_categories,
                    )
            return evidence

        return evidence
