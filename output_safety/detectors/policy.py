"""
Output Policy Detector.

Evaluates model responses against output safety policies:
- System prompt leak / internal directive exposure
- Dangerous exploit payload generation
- Raw command execution scripts
"""

from __future__ import annotations

import logging
import re
from typing import Dict

logger = logging.getLogger(__name__)


class OutputPolicyDetector:
    """
    Evaluates model outputs against security policy constraints.
    """

    SYSTEM_PROMPT_LEAK_PATTERNS = [
        re.compile(r"(?i)\b(?:you are an ai developed by|system instructions:|system prompt:|base directives:)\b"),
        re.compile(r"(?i)\b(?:my developer instructions are|initial instructions given to me:)\b"),
    ]

    EXPLOIT_PATTERNS = [
        re.compile(r"(?i)\b(?:import pty;\s*pty\.spawn|nc -e /bin/(?:bash|sh)|/bin/bash -i >& /dev/tcp/)\b"),
        re.compile(r"(?i)\b(?:powershell -e [A-Za-z0-9+/=]{40,}|powershell -enc [A-Za-z0-9+/=]{40,})\b"),
    ]

    def evaluate(self, text: str) -> Dict[str, float]:
        """
        Scan response text for policy violations.
        """
        if not text:
            return {}

        scores: Dict[str, float] = {}

        for pattern in self.SYSTEM_PROMPT_LEAK_PATTERNS:
            if pattern.search(text):
                scores["policy_system_prompt_leak"] = 0.90
                break

        for pattern in self.EXPLOIT_PATTERNS:
            if pattern.search(text):
                scores["policy_exploit_payload"] = 1.0
                break

        return scores
