"""
Request Pipeline — Single Authoritative Entrypoint for all AI Requests.

Enforces strict, mandatory, sequential execution:
  1. Synchronous In-line Evidence Generation (ClassifierService.classify)
  2. Policy Decision (PolicyEngine.evaluate)
  3. Conditional Escalation Loop (LocalJudge -> JudgeEvidence -> PolicyEngine.evaluate)
  4. Secure Enforcement & Routing (RouterService.route -> NORMAL, RESTRICTED, BLOCK)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from classifier.service import ClassifierService
from policy.engine import PolicyEngine
from policy.models import PolicyDecision, Route
from router.service import RouterService
from shield.judge import LocalJudge
from schemas import ChatRequest, ChatResponse

logger = logging.getLogger(__name__)


class RequestPipeline:
    """
    Central request pipeline orchestrating evidence extraction, policy governance,
    and backend routing without any asynchronous background tasks.
    """

    def __init__(
        self,
        classifier: ClassifierService,
        policy_engine: PolicyEngine,
        router: RouterService,
        judge: Optional[LocalJudge] = None,
    ) -> None:
        self.classifier = classifier
        self.policy_engine = policy_engine
        self.router = router
        self.judge = judge or LocalJudge()

    async def process(
        self,
        request: ChatRequest,
        metadata: Optional[dict[str, Any]] = None,
    ) -> tuple[ChatResponse, PolicyDecision]:
        """
        Process request through the mandatory security chain:
          classify -> policy -> (optional judge escalation -> re-evaluate) -> route
        """
        meta_dict = metadata or (request.metadata.model_dump() if request.metadata else {})
        messages_list = [msg.model_dump() for msg in request.messages] if request.messages else []

        # 1. Mandatory In-line Synchronous Evidence Generation
        evidence = self.classifier.classify(
            request.get_full_text(),
            messages=messages_list,
            metadata=meta_dict,
        )

        # 2. Declarative Policy Evaluation
        decision = self.policy_engine.evaluate(evidence, metadata=meta_dict)

        # 3. Conditional Escalation & Re-Evaluation Loop (Single bounded cycle)
        if decision.route == Route.ESCALATE:
            logger.info("Decision is ESCALATE -> Invoking LocalJudge for secondary evidence generation")
            judge_evidence = self.judge.adjudicate(request.get_full_text(), evidence=evidence)
            evidence.judge_evidence = judge_evidence
            decision = self.policy_engine.evaluate(
                evidence,
                metadata=meta_dict,
                escalate_cycle_count=decision.escalate_cycle_count,
            )
            logger.info("Post-Escalation Final Decision: %s (%s)", decision.route.value, decision.reason)

        # 4. PEP Router Execution (Mechanically enforces decision)
        response = await self.router.route(decision, request)

        return response, decision
