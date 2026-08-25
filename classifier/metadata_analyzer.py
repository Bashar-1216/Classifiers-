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

logger = logging.getLogger(__name__)


class MetadataAnalyzer:
    """
    Evaluates request caller metadata and privilege boundaries.
    """

    def __init__(self) -> None:
        logger.info("MetadataAnalyzer initialized.")

    def evaluate(self, metadata: dict[str, Any] | None) -> dict[str, float]:
        """
        Analyze metadata dictionary for environmental or privilege risk modifiers.

        Args:
            metadata: Request metadata (user_role, project_sensitivity, environment, etc.)

        Returns:
            Dictionary mapping metadata risk tags to confidence scores (0.0 to 1.0).
        """
        scores: dict[str, float] = {}

        if not metadata:
            return scores

        # 1. User Role Risk Modifier
        user_role = str(metadata.get("user_role", "")).lower()
        if user_role in ("guest", "anonymous", "external_untrusted", "public"):
            scores["metadata_untrusted_external_role"] = 0.40
        elif user_role in ("contractor", "intern"):
            scores["metadata_restricted_internal_role"] = 0.20

        # 2. Project Sensitivity / Data Classification
        project_sensitivity = str(metadata.get("project_sensitivity", metadata.get("data_classification", ""))).lower()
        if project_sensitivity in ("strictly_confidential", "top_secret", "m_and_a", "financial_unreleased"):
            scores["metadata_strictly_confidential_project"] = 0.90
        elif project_sensitivity in ("confidential", "internal_only", "restricted"):
            scores["metadata_confidential_project"] = 0.70

        # 3. Environment Origin
        environment = str(metadata.get("environment", metadata.get("origin", ""))).lower()
        if environment in ("public_internet", "untrusted_dmz", "third_party_webhook"):
            scores["metadata_untrusted_network_origin"] = 0.35

        return scores
