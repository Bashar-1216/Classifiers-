"""
Request Pipeline — Single Authoritative Entrypoint for all AI Requests.

Enforces strict, mandatory, sequential execution:
  1. Synchronous In-line Classification (ClassifierService.classify)
  2. Policy Decision (PolicyEngine.evaluate)
  3. Secure Routing (RouterService.route -> NORMAL or SHIELD)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from classifier.service import ClassifierService
from policy.engine import PolicyEngine
from policy.models import PolicyDecision
from router.service import RouterService
from router.shield_backend import ShieldUnavailableError
from schemas import ChatRequest, ChatResponse

logger = logging.getLogger(__name__)


class RequestPipeline:
    """
    Central request pipeline orchestrating classification, policy governance,
    and backend routing without any asynchronous background tasks.
    """

    def __init__(
        self,
        classifier: ClassifierService,
        policy_engine: PolicyEngine,
        router: RouterService,
    ) -> None:
        self.classifier = classifier
        self.policy_engine = policy_engine
        self.router = router

    async def process(
        self,
        request: ChatRequest,
        metadata: Optional[dict[str, Any]] = None,
    ) -> tuple[ChatResponse, PolicyDecision]:
        """
        Process request through the mandatory security chain:
          classify -> policy -> route
        """
        meta_dict = metadata or (request.metadata.model_dump() if request.metadata else {})
        messages_list = [msg.model_dump() for msg in request.messages] if request.messages else []

        # 1. Mandatory In-line Synchronous Classification
        classification = self.classifier.classify(
            request.get_full_text(),
            messages=messages_list,
            metadata=meta_dict,
        )

        # 2. Declarative Policy Evaluation
        decision = self.policy_engine.evaluate(classification, metadata=meta_dict)

        # 3. Router Execution (dispatches to NORMAL or SHIELD, fails closed on Shield error)
        response = await self.router.route(decision, request)

        return response, decision
