"""
Metadata Analyzer — User Identity, Role, and Environment Assessment.

Evaluates request metadata:
- User role & privilege level (external_guest, contractor, employee, admin)
- Data classification / Project sensitivity (public, internal, confidential, strictly_confidential)
- Environment origin (public_app, untrusted_api, internal_vpn, secure_enclave)
"""

from __future__ import annotations

import logging
from typing import Any

from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class MetadataAnalyzer:
    """
    Evaluates request caller metadata and privilege boundaries using declarative security knowledge.
    """

    def __init__(self) -> None:
        bundle = KnowledgeLoader.get_bundle()
        self.modifiers = bundle.metadata_modifiers
        logger.info("MetadataAnalyzer initialized with declarative security knowledge.")

    def evaluate(self, metadata: dict[str, Any] | None) -> dict[str, float]:
        """
        Analyze metadata dictionary for environmental or privilege risk modifiers.
        """
        scores: dict[str, float] = {}

        if not metadata or not self.modifiers:
            return scores

        # 1. User Role Risk Modifier
        user_role = str(metadata.get("user_role", "")).lower()
        if user_role:
            for group, cfg in self.modifiers.get("user_roles", {}).items():
                if user_role in cfg.get("values", []):
                    scores[cfg.get("category", f"metadata_{group}")] = cfg.get("score", 0.40)

        # 2. Project Sensitivity / Data Classification
        project_sensitivity = str(metadata.get("project_sensitivity", metadata.get("data_classification", ""))).lower()
        if project_sensitivity:
            for group, cfg in self.modifiers.get("project_sensitivities", {}).items():
                if project_sensitivity in cfg.get("values", []):
                    scores[cfg.get("category", f"metadata_{group}")] = cfg.get("score", 0.70)

        # 3. Environment Origin
        environment = str(metadata.get("environment", metadata.get("origin", ""))).lower()
        if environment:
            for group, cfg in self.modifiers.get("environment_origins", {}).items():
                if environment in cfg.get("values", []):
                    scores[cfg.get("category", f"metadata_{group}")] = cfg.get("score", 0.35)

        return scores
