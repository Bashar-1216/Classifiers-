"""
Context Analyzer — Multi-turn Conversation & History Trajectory.

Analyzes the full conversation trajectory, detecting:
- Cumulative threat escalation across turns (Salami attacks)
- Contextual reference execution (e.g., Turn 1 quotes attack -> Turn 2 says "apply it")
- Repeated security probing across session history (multilingual declarative terms)
- In-band role spoofing progression across turns
- Contextual drift from innocent topics to sensitive domains
"""

from __future__ import annotations

import logging
import re
from typing import Any

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class ContextAnalyzer:
    """
    Evaluates multi-turn conversation context and history trajectory.
    """

    def __init__(
        self,
        max_history_turns: int = 20,
        probing_terms: list[str] | None = None,
        execution_regexes: list[re.Pattern] | None = None,
    ) -> None:
        self.max_history_turns = max_history_turns
        bundle = KnowledgeLoader.get_bundle()
        self.probing_terms = probing_terms or bundle.context_probing_terms
        self.execution_regexes = execution_regexes or bundle.context_execution_regexes
        self.rules = bundle.multi_turn_rules

        # Precompile multi-turn regexes from bundle
        self.quoted_attack_regex = re.compile(self.rules.get("quoted_attack_marker", r'(?i)["«“\'].*?(?:ignore|reveal|system\s+prompt|تعليمات|اكشف).*?["»”\']'))
        self.sensitive_probe_regex = re.compile(self.rules.get("sensitive_asset_probe_pattern", r'(?i)\b(?:أي\s+منها\s+موجود\s+عندك|هل\s+عندك|ما\s+الموجود\s+عندك|do\s+you\s+have\s+any)\b'))
        self.persona_spoof_regex = re.compile(self.rules.get("persona_spoof_pattern", r'(?i)\b(?:admin|authorized|superadmin|security\s+engineer|مدير|مسؤول|developer|root)\b'))
        self.sensitive_terms = self.rules.get("sensitive_asset_terms", [])
        self.salami_var_markers = self.rules.get("salami_variable_markers", [])
        self.salami_combiners = self.rules.get("salami_combiner_verbs", [])
        self.persona_escalators = self.rules.get("persona_escalation_verbs", [])

        logger.info("ContextAnalyzer initialized with declarative security knowledge (window=%d turns, terms=%d).", max_history_turns, len(self.probing_terms))

    def evaluate(self, messages: list[dict[str, Any]]) -> dict[str, float]:
        """
        Analyze multi-turn message history for cumulative risk using declarative security knowledge.
        """
        scores: dict[str, float] = {}

        if not messages or len(messages) <= 1:
            return scores

        user_messages = [m.get("content", "") for m in messages if m.get("role") == "user"]
        if not user_messages:
            return scores

        total_turns = len(user_messages)
        current_msg = user_messages[-1]
        prior_messages = user_messages[:-1]

        # 1. Multi-turn Quoted Attack Execution Trap
        prior_contains_attack_quote = any(self.quoted_attack_regex.search(m) for m in prior_messages)
        has_execution_command = any(rx.search(current_msg) for rx in self.execution_regexes)
        if prior_contains_attack_quote and has_execution_command:
            scores["multi_turn_quoted_attack_execution"] = 0.95

        # 2. Repeated Security Probing Across History
        probe_count = 0
        for msg in user_messages:
            msg_lower = msg.lower()
            if any(term in msg_lower for term in self.probing_terms):
                probe_count += 1

        # Check if current turn asks existence/extraction based on prior probe
        has_prior_sensitive_topic = any(
            any(w in m.lower() for w in self.sensitive_terms)
            for m in prior_messages
        )
        if has_prior_sensitive_topic and self.sensitive_probe_regex.search(current_msg):
            scores["multi_turn_sensitive_asset_probing"] = 0.90
        elif probe_count >= 2:
            scores["multi_turn_repeated_security_probing"] = min(0.95, 0.50 + (probe_count * 0.15))

        # 3. Salami Attack / Cumulative Payload Splitting across turns
        has_variable_def = any(any(v in m.lower() for v in self.salami_var_markers) for m in prior_messages)
        has_combiner_last = any(w in current_msg.lower() for w in self.salami_combiners)
        if has_variable_def and has_combiner_last:
            scores["multi_turn_salami_assembly"] = 0.88

        # 4. Multi-turn Persona Spoof Escalation
        prior_spoofs = any(self.persona_spoof_regex.search(m) for m in prior_messages)
        if prior_spoofs and any(w in current_msg.lower() for w in self.persona_escalators):
            scores["multi_turn_identity_spoof_escalation"] = 0.90

        # 5. Conversation length and drift factor
        if total_turns > 15:
            scores["extended_session_fatigue_risk"] = 0.30

        return scores
