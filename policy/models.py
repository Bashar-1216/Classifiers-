"""
Policy Decision Models, Key Management & Cryptographic Provenance.

Defines the routing decision types used by the Policy Decision Layer (PRD §6.5).
The Policy Engine is the SOLE authoritative component that transforms SecurityEvidence
into a cryptographically signed, immutable PolicyDecision that the PEP/Router enforces.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field

from classifier.evidence_models import SecurityEvidence
from classifier.models import ClassificationResult

logger = logging.getLogger(__name__)

# Dynamic Secret Key Store (In-Memory per session if not set in ENV, zero hardcoded static strings)
_RUNTIME_SESSION_KEY: str | None = None


def get_pdp_signing_secret() -> str:
    """
    Retrieve PDP signing secret securely from environment or active session key store.
    Strictly forbids hardcoded fallback keys in production.
    """
    global _RUNTIME_SESSION_KEY
    env_secret = os.getenv("PDP_SIGNING_KEY")
    if env_secret:
        return env_secret

    if os.getenv("ENVIRONMENT", "").lower() == "production" or os.getenv("PDP_STRICT_SECURITY", "").lower() == "true":
        raise RuntimeError("CRITICAL SECURITY ERROR: PDP_SIGNING_KEY must be configured in production environment.")

    if _RUNTIME_SESSION_KEY is None:
        _RUNTIME_SESSION_KEY = secrets.token_hex(32)
        logger.info("Initialized ephemeral cryptographically random PDP signing key for runtime session.")

    return _RUNTIME_SESSION_KEY


class Route(str, Enum):
    """Authoritative routing and policy action destinations."""

    NORMAL = "NORMAL"
    RESTRICTED = "RESTRICTED"
    SHIELD = "SHIELD"  # Alias to RESTRICTED for backwards compatibility
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"
    UNAVAILABLE = "UNAVAILABLE"
    CLOUD = "CLOUD"
    LOCAL_SHIELD = "LOCAL_SHIELD"
    LOCAL_PRIVATE = "LOCAL_PRIVATE"


class RailHealthStatus(str, Enum):
    """Operational health semantics for security rails."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class PolicyDecision(BaseModel):
    """
    Authoritative, cryptographically verifiable output of the Policy Decision Point (PDP).

    Carries full policy provenance and integrity guarantees:
    - decision_id: Unique UUID
    - request_id: Unique request binding
    - route: Authoritative target route/action
    - policy_version: Version of the active policy schema
    - reason_codes: Structured policy trigger codes
    - permitted_route: Mechanically allowed egress destination class
    - permitted_destinations: Concrete allowlisted target endpoints
    - cloud_fallback: Hard invariant flag (strictly False for restricted traffic)
    - issued_at: UNIX timestamp of issuance
    - expires_at: UNIX timestamp of expiry (TTL protection)
    - signature: HMAC-SHA256 signature from PDP covering complete provenance
    """

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = Field(default="req-default", description="Bound request identifier")
    route: Route = Field(
        ...,
        description="Where to route this request: NORMAL, RESTRICTED, BLOCK, ESCALATE, UNAVAILABLE",
    )
    policy_version: str = Field(default="1.0.0", description="Policy version")
    reason_codes: list[str] = Field(default_factory=list, description="Structured policy trigger codes")
    reason: str = Field(
        ...,
        description="Human-readable explanation of the routing decision",
    )
    permitted_route: str = Field(default="NORMAL", description="Mechanically allowed destination class")
    permitted_destinations: list[str] = Field(default_factory=list, description="Allowlisted destination URLs/endpoints")
    cloud_fallback: bool = Field(default=False, description="Strict fail-closed zero-cloud invariant")
    execution_status: Optional[str] = Field(default=None, description="Operational status if degraded/unavailable")
    issued_at: float = Field(default_factory=time.time, description="Unix timestamp of decision issuance")
    expires_at: float = Field(default_factory=lambda: time.time() + 60.0, description="Expiry timestamp (TTL 60s)")
    signature: Optional[str] = Field(default=None, description="HMAC-SHA256 signature from PDP")
    rail_health: dict[str, str] = Field(default_factory=dict, description="Health status of evaluated rails")

    evidence: Optional[SecurityEvidence] = Field(default=None, description="The security evidence evaluated")
    classification_result: Optional[ClassificationResult] = Field(
        default=None,
        description="Legacy alias for backwards compatibility",
    )
    escalate_cycle_count: int = Field(default=0, description="Tracks escalation depth to prevent infinite loops")

    @property
    def decision(self) -> Route:
        """Alias for route."""
        return self.route

    def compute_signature_payload(self) -> str:
        """Construct canonical string of all immutable decision and provenance attributes."""
        payload_dict = {
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "route": self.route.value,
            "policy_version": self.policy_version,
            "reason_codes": sorted(self.reason_codes),
            "permitted_route": self.permitted_route,
            "permitted_destinations": sorted(self.permitted_destinations),
            "cloud_fallback": self.cloud_fallback,
            "execution_status": self.execution_status or "",
            "rail_health": {k: str(v) for k, v in sorted(self.rail_health.items())},
            "escalate_cycle_count": self.escalate_cycle_count,
            "issued_at": round(self.issued_at, 2),
            "expires_at": round(self.expires_at, 2),
        }
        return json.dumps(payload_dict, sort_keys=True)

    def sign(self, secret_key: Optional[str] = None) -> str:
        """Sign this PolicyDecision with HMAC-SHA256 and store in signature field."""
        key = secret_key or get_pdp_signing_secret()
        canonical_str = self.compute_signature_payload()
        sig = hmac.new(key.encode("utf-8"), canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()
        self.signature = sig
        return sig

    def verify_integrity(self, expected_request_id: Optional[str] = None, secret_key: Optional[str] = None) -> tuple[bool, str]:
        """
        Verify decision cryptographic integrity, timestamp validity, and request binding.
        """
        # 1. Signature presence and correctness
        if not self.signature:
            return False, "UNSIGNED_DECISION: Missing cryptographic signature from PDP"

        key = secret_key or get_pdp_signing_secret()
        canonical_str = self.compute_signature_payload()
        expected_sig = hmac.new(key.encode("utf-8"), canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(self.signature, expected_sig):
            return False, "MUTATED_DECISION: Signature mismatch or decision tampering detected"

        # 2. TTL Expiry check
        current_time = time.time()
        if current_time > self.expires_at:
            return False, f"EXPIRED_DECISION: Decision expired at {self.expires_at} (current {current_time})"

        # 3. Request binding check
        if expected_request_id and self.request_id != expected_request_id:
            return False, f"REQUEST_MISMATCH: Decision bound to {self.request_id}, but request is {expected_request_id}"

        # 4. Invariant checks
        if self.route in (Route.RESTRICTED, Route.SHIELD, Route.LOCAL_SHIELD):
            if self.cloud_fallback:
                return False, "ILLEGAL_INVARIANT: RESTRICTED decision cannot have cloud_fallback=True"
            if self.permitted_destinations:
                for d in self.permitted_destinations:
                    d_lower = d.lower()
                    is_local_shield = ("shield" in d_lower) or ("local" in d_lower) or ("127.0.0.1" in d_lower) or ("localhost" in d_lower)
                    if not is_local_shield or "groq" in d_lower or "openai" in d_lower or "cloud" in d_lower:
                        return False, f"ILLEGAL_DESTINATION: RESTRICTED decision cannot list non-shield destination: {d}"

        return True, "VALID"
