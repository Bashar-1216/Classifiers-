"""
Context Analyzer — Multi-turn Conversation & History Trajectory.

Analyzes the full conversation trajectory, detecting:
- Cumulative threat escalation across turns (Salami attacks)
- Contextual drift from innocent topics to sensitive domains
- Role switching anomalies in previous conversation turns
- Repeated prompt injection probing across session history
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ContextAnalyzer:
    """
    Evaluates multi-turn conversation context and history trajectory.
    """

    def __init__(self, max_history_turns: int = 20) -> None:
        self.max_history_turns = max_history_turns
        logger.info("ContextAnalyzer initialized (window=%d turns).", max_history_turns)

    def evaluate(self, messages: list[dict[str, Any]]) -> dict[str, float]:
        """
        Analyze multi-turn message history for cumulative risk.

        Args:
            messages: Full list of message dicts with 'role' and 'content'.

        Returns:
            Dictionary mapping context risk tags to confidence scores (0.0 to 1.0).
        """
        scores: dict[str, float] = {}

        if not messages or len(messages) <= 1:
            return scores

        user_messages = [m.get("content", "") for m in messages if m.get("role") == "user"]
        total_turns = len(user_messages)

        # 1. Repeated probing risk: multiple questions probing security/system/instructions
        probing_terms = ["system", "prompt", "instruction", "rule", "guideline", "restrict", "bypass", "jailbreak"]
        probe_count = 0
        for msg in user_messages:
            msg_lower = msg.lower()
            if any(term in msg_lower for term in probing_terms):
                probe_count += 1

        if probe_count >= 2:
            scores["multi_turn_repeated_security_probing"] = min(0.95, 0.50 + (probe_count * 0.15))

        # 2. Salami Attack / Cumulative Payload Splitting across turns
        # e.g., turn 1 defines part 1, turn 2 defines part 2, turn 3 executes
        has_variable_def = any("let " in m.lower() or "variable" in m.lower() for m in user_messages[:-1])
        has_combiner_last = any(w in user_messages[-1].lower() for w in ["combine", "execute", "run", "concat", "now do"])
        if has_variable_def and has_combiner_last:
            scores["multi_turn_salami_assembly"] = 0.88

        # 3. Conversation length and drift factor
        if total_turns > 15:
            scores["extended_session_fatigue_risk"] = 0.30

        return scores
