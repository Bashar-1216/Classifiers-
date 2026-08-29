"""
Declarative Policy Decision Point (PDP) — Phase 1.1 Sealed Engine.

Authoritative decision maker that enforces:
1. Strict distinction between Calibrated Probabilities and Uncalibrated Heuristic/Similarity Signals.
2. Multilateral Evidence Synthesis: JudgeEvidence is an additional signal, not a hard override.
3. Execution-Constrained Shield Health Gating: Shield outage fails closed ONLY for RESTRICTED traffic.
4. Cryptographically signed policy decisions with complete provenance.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from classifier.evidence_models import ScoreType, SecurityEvidence
from classifier.guard_models import GuardEvidence, GuardVerdict
from policy.models import PolicyDecision, RailHealthStatus, Route, get_pdp_signing_secret

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATH = Path(__file__).parent / "policies.json"


class PolicyEngine:
    """
    Authoritative Policy Decision Engine (PDP).
    Transforms multi-rail SecurityEvidence into signed, deterministic PolicyDecision.
    """

    POLICY_VERSION = "1.1.0"

    def __init__(self, policy_file: Path | str | None = None) -> None:
        self.policy_file = Path(policy_file) if policy_file else DEFAULT_POLICY_PATH
        self.policies: dict[str, Any] = {}
        self.rules: list[dict[str, Any]] = []
        self.default_route = Route.NORMAL
        self.load_policies()

    def load_policies(self) -> None:
        """Load declarative policy rules from JSON policy store."""
        if self.policy_file.exists():
            try:
                with open(self.policy_file, "r", encoding="utf-8") as f:
                    self.policies = json.load(f)
                    self.rules = self.policies.get("rules", [])
                logger.info("PolicyEngine loaded %d declarative rules from %s", len(self.rules), self.policy_file)
                return
            except Exception as exc:
                logger.warning("Failed to load policy file %s: %s", self.policy_file, exc)

        self.rules = [
            {"id": "POL-GUARD-001", "name": "Neural Guard Threat", "guard_verdict": "UNSAFE", "action": "SHIELD"},
            {"id": "POL-GUARD-002", "name": "Neural Guard Fail-Closed", "guard_verdict": "UNAVAILABLE", "action": "SHIELD"},
            {"id": "POL-001", "name": "Security & Jailbreak", "category": "security", "min_score": 0.5, "action": "SHIELD"},
            {"id": "POL-006", "name": "Credential & PII", "category": "privacy", "min_score": 0.5, "action": "SHIELD"},
        ]

    def _get_calibrated_probability(self, signal: Any) -> float | None:
        """Extract empirical calibrated probability if and only if calibrated."""
        if signal is None:
            return None
        if getattr(signal, "score_type", None) == ScoreType.PROBABILITY:
            return getattr(signal, "raw_score", None)
        return getattr(signal, "calibrated_probability", None)

    def evaluate(
        self,
        evidence: Any,
        metadata: dict[str, Any] | None = None,
        guard_evidence: Optional[GuardEvidence] = None,
        escalate_cycle_count: int = 0,
        rail_health: dict[str, str] | None = None,
    ) -> PolicyDecision:
        """
        Authoritatively evaluate SecurityEvidence and produce a signed PolicyDecision.
        """
        try:
            meta = metadata or {}
            req_id = meta.get("request_id", getattr(evidence, "request_id", f"req-{uuid.uuid4().hex[:8]}"))
            reasons_list = getattr(evidence, "reasons", []) or getattr(evidence, "all_reasons", [])
            reasons_str = " ".join(str(r) for r in reasons_list)
            categories = getattr(evidence, "categories", {}) or {}
            health_map = rail_health or {}

            prompt_attack = getattr(evidence, "prompt_attack", None)
            content_risk = getattr(evidence, "content_risk", None)
            dlp_obj = getattr(evidence, "dlp", None)
            judge_ev = getattr(evidence, "judge_evidence", None)

            # -----------------------------------------------------------------
            # 1. HARD INVARIANTS: DLP Secrets & Credential Protection (Precedence 0)
            # -----------------------------------------------------------------
            is_dlp_unavailable = health_map.get("dlp") in (
                RailHealthStatus.UNAVAILABLE.value,
                RailHealthStatus.TIMEOUT.value,
                RailHealthStatus.ERROR.value,
            )
            if is_dlp_unavailable:
                decision = PolicyDecision(
                    request_id=req_id,
                    route=Route.BLOCK,
                    policy_version=self.POLICY_VERSION,
                    reason_codes=["DLP_RAIL_UNAVAILABLE_FAIL_CLOSED"],
                    reason="BLOCK — Required DLP security rail is unavailable; failing closed.",
                    permitted_route="NONE",
                    permitted_destinations=[],
                    cloud_fallback=False,
                    rail_health=health_map,
                    evidence=evidence if isinstance(evidence, SecurityEvidence) else None,
                    classification_result=evidence,
                )
                decision.sign()
                return decision

            if dlp_obj and (dlp_obj.hard_invariant_violation or dlp_obj.has_credentials):
                # Hard invariant violation ALWAYS blocks regardless of Judge SAFE
                decision = PolicyDecision(
                    request_id=req_id,
                    route=Route.BLOCK,
                    policy_version=self.POLICY_VERSION,
                    reason_codes=["DLP_HARD_INVARIANT_VIOLATION"],
                    reason="BLOCK — Hard security invariant violated: sensitive credentials/secrets detected.",
                    permitted_route="NONE",
                    permitted_destinations=[],
                    cloud_fallback=False,
                    rail_health=health_map,
                    evidence=evidence if isinstance(evidence, SecurityEvidence) else None,
                    classification_result=evidence,
                )
                decision.sign()
                return decision

            # -----------------------------------------------------------------
            # 2. REQUIRED RAIL HEALTH FAIL-CLOSED GATING
            # -----------------------------------------------------------------
            is_prompt_rail_down = health_map.get("prompt_attack") in (
                RailHealthStatus.UNAVAILABLE.value,
                RailHealthStatus.TIMEOUT.value,
                RailHealthStatus.ERROR.value,
            )
            if is_prompt_rail_down:
                # Prompt rail outage requires Shield isolation
                return self._finalize_restricted_decision(
                    req_id=req_id,
                    reason_codes=["PROMPT_ATTACK_RAIL_TIMEOUT_FAIL_CLOSED"],
                    reason="RESTRICTED — Prompt attack rail timed out or unavailable; failing closed to Shield.",
                    health_map=health_map,
                    evidence=evidence,
                    escalate_cycle_count=escalate_cycle_count,
                )

            # -----------------------------------------------------------------
            # 3. NEURAL GUARD SUBSYSTEM CHECKS
            # -----------------------------------------------------------------
            has_guard_unsafe = (guard_evidence and guard_evidence.verdict == GuardVerdict.UNSAFE) or ("neural_guard_unsafe" in reasons_str)
            has_guard_unavailable = (guard_evidence and guard_evidence.verdict == GuardVerdict.UNAVAILABLE) or ("neural_guard_unavailable" in reasons_str)

            if has_guard_unsafe:
                return self._finalize_restricted_decision(
                    req_id=req_id,
                    reason_codes=["POL-GUARD-001", "NEURAL_GUARD_UNSAFE"],
                    reason="RESTRICTED — [POL-GUARD-001]: Neural Guard identified active semantic hazard.",
                    health_map=health_map,
                    evidence=evidence,
                    escalate_cycle_count=escalate_cycle_count,
                )

            if has_guard_unavailable:
                return self._finalize_restricted_decision(
                    req_id=req_id,
                    reason_codes=["POL-GUARD-002", "NEURAL_GUARD_UNAVAILABLE"],
                    reason="RESTRICTED — [POL-GUARD-002]: Fail-Closed triggered due to Guard service unavailability.",
                    health_map=health_map,
                    evidence=evidence,
                    escalate_cycle_count=escalate_cycle_count,
                )

            # -----------------------------------------------------------------
            # 4. MULTILATERAL EVALUATION WITH JUDGE EVIDENCE (Post-Escalation)
            # -----------------------------------------------------------------
            if judge_ev is not None:
                j_verdict = judge_ev.verdict.upper()

                if j_verdict == "UNSAFE":
                    return self._finalize_restricted_decision(
                        req_id=req_id,
                        reason_codes=["JUDGE_ADJUDICATED_UNSAFE"] + judge_ev.hazard_categories,
                        reason=f"RESTRICTED — Local Judge confirmed threat: {judge_ev.adjudication_reason}",
                        health_map=health_map,
                        evidence=evidence,
                        escalate_cycle_count=escalate_cycle_count + 1,
                    )
                elif j_verdict in ("ERROR", "TIMEOUT", "UNCERTAIN"):
                    return self._finalize_restricted_decision(
                        req_id=req_id,
                        reason_codes=["JUDGE_UNCERTAIN_FAIL_CLOSED"],
                        reason="RESTRICTED — Local Judge timed out or uncertain; failing closed to Air-Gapped Shield.",
                        health_map=health_map,
                        evidence=evidence,
                        escalate_cycle_count=escalate_cycle_count + 1,
                    )
                elif j_verdict == "SAFE":
                    # Judge says SAFE: Synthesize with remaining rails.
                    # Verify no declarative category violations or high calibrated risk exists.
                    has_active_category_violation = False
                    for rule in self.rules:
                        if "category" in rule:
                            cat_name = rule["category"]
                            min_score = float(rule.get("min_score", 0.50))
                            cat_score = max([v for k, v in categories.items() if cat_name in k], default=categories.get(cat_name, 0.0))
                            if cat_score >= min_score and cat_name != "security":
                                has_active_category_violation = True
                                break

                    if has_active_category_violation:
                        return self._finalize_restricted_decision(
                            req_id=req_id,
                            reason_codes=["JUDGE_OVERRIDDEN_BY_CONTENT_RISK"],
                            reason="RESTRICTED — Local Judge reported SAFE, but active non-security risk policy triggered.",
                            health_map=health_map,
                            evidence=evidence,
                            escalate_cycle_count=escalate_cycle_count + 1,
                        )

                    # Ambiguity resolved as safe
                    decision = PolicyDecision(
                        request_id=req_id,
                        route=Route.NORMAL,
                        policy_version=self.POLICY_VERSION,
                        reason_codes=["JUDGE_ADJUDICATED_SAFE"],
                        reason=f"NORMAL — Local Judge cleared ambiguity: {judge_ev.adjudication_reason}",
                        permitted_route="NORMAL",
                        permitted_destinations=["cloud.approved.normal"],
                        cloud_fallback=False,
                        evidence=evidence if isinstance(evidence, SecurityEvidence) else None,
                        classification_result=evidence,
                        escalate_cycle_count=escalate_cycle_count + 1,
                        rail_health=health_map,
                    )
                    decision.sign()
                    return decision

            # -----------------------------------------------------------------
            # 5. CALIBRATED PROBABILITY RISK EVALUATION
            # -----------------------------------------------------------------
            direct_inj_prob = self._get_calibrated_probability(prompt_attack.direct_injection) if prompt_attack else None
            cyber_prob = self._get_calibrated_probability(content_risk.unauthorized_cyber_intent) if content_risk else None

            if direct_inj_prob is not None and direct_inj_prob >= 0.70:
                return self._finalize_restricted_decision(
                    req_id=req_id,
                    reason_codes=["CALIBRATED_PROBABILITY_ATTACK_HIGH"],
                    reason=f"RESTRICTED — High calibrated probability of prompt attack (P={direct_inj_prob:.2f}).",
                    health_map=health_map,
                    evidence=evidence,
                    escalate_cycle_count=escalate_cycle_count,
                )

            if cyber_prob is not None and cyber_prob >= 0.70:
                return self._finalize_restricted_decision(
                    req_id=req_id,
                    reason_codes=["CALIBRATED_PROBABILITY_CYBER_HIGH"],
                    reason=f"RESTRICTED — High calibrated probability of cyber risk (P={cyber_prob:.2f}).",
                    health_map=health_map,
                    evidence=evidence,
                    escalate_cycle_count=escalate_cycle_count,
                )

            # -----------------------------------------------------------------
            # 6. DECLARATIVE CATEGORY RULES EVALUATION
            # -----------------------------------------------------------------
            for rule in self.rules:
                action_str = rule.get("action", "SHIELD").upper()
                action_route = Route[action_str]

                if "category" in rule:
                    cat_name = rule["category"]
                    min_score = float(rule.get("min_score", 0.50))
                    matching_scores = [v for k, v in categories.items() if cat_name in k]
                    cat_score = max(matching_scores) if matching_scores else categories.get(cat_name, 0.0)

                    if cat_score >= min_score:
                        is_restricted = action_route in (Route.SHIELD, Route.RESTRICTED)
                        if is_restricted:
                            return self._finalize_restricted_decision(
                                req_id=req_id,
                                reason_codes=[rule.get("id", "POL"), f"CATEGORY_{cat_name.upper()}"],
                                reason=(
                                    f"RESTRICTED — Triggered Policy [{rule.get('id', 'POL')} - {rule.get('name')}]: "
                                    f"category '{cat_name}' score {cat_score:.2f} >= threshold {min_score:.2f}"
                                ),
                                health_map=health_map,
                                evidence=evidence,
                                escalate_cycle_count=escalate_cycle_count,
                            )
                        else:
                            decision = PolicyDecision(
                                request_id=req_id,
                                route=action_route,
                                policy_version=self.POLICY_VERSION,
                                reason_codes=[rule.get("id", "POL"), f"CATEGORY_{cat_name.upper()}"],
                                reason=f"Triggered Policy [{rule.get('id', 'POL')}]: allow.",
                                permitted_route="NORMAL",
                                permitted_destinations=["cloud.approved.normal"],
                                cloud_fallback=False,
                                rail_health=health_map,
                                evidence=evidence if isinstance(evidence, SecurityEvidence) else None,
                                classification_result=evidence,
                            )
                            decision.sign()
                            return decision

            # -----------------------------------------------------------------
            # 7. TRANSIENT ESCALATION: Uncalibrated Gray-Zone Ambiguity
            # -----------------------------------------------------------------
            raw_attack_score = prompt_attack.get_max_score() if prompt_attack else getattr(evidence, "risk_score", 0.0)
            raw_cyber_score = content_risk.unauthorized_cyber_intent.raw_score if content_risk else 0.0

            script_prof = getattr(evidence, "script_profile", None)
            is_gray_zone = (0.30 <= raw_attack_score < 0.70) or (0.30 <= raw_cyber_score < 0.70)
            has_contextual_ambiguity = script_prof and (script_prof.mixed_script or script_prof.arabizi_likelihood >= 0.50)

            if escalate_cycle_count == 0 and is_gray_zone and has_contextual_ambiguity:
                decision = PolicyDecision(
                    request_id=req_id,
                    route=Route.ESCALATE,
                    policy_version=self.POLICY_VERSION,
                    reason_codes=["ESCALATE_GRAY_ZONE_UNCERTAINTY"],
                    reason="ESCALATE — Ambiguous uncalibrated signals with contextual factors; requesting Local Judge adjudication.",
                    permitted_route="NONE",
                    permitted_destinations=["judge.internal.local"],
                    cloud_fallback=False,
                    rail_health=health_map,
                    evidence=evidence if isinstance(evidence, SecurityEvidence) else None,
                    classification_result=evidence,
                    escalate_cycle_count=1,
                )
                decision.sign()
                return decision

            # -----------------------------------------------------------------
            # 8. LEGACY UNCALIBRATED SIMILARITY THRESHOLDS (Compatibility Fallback)
            # -----------------------------------------------------------------
            if raw_attack_score >= 0.70:
                return self._finalize_restricted_decision(
                    req_id=req_id,
                    reason_codes=["LEGACY_UNCALIBRATED_SIMILARITY_ATTACK_HIGH"],
                    reason=f"RESTRICTED — [Legacy Fallback] High uncalibrated similarity match ({raw_attack_score:.2f}).",
                    health_map=health_map,
                    evidence=evidence,
                    escalate_cycle_count=escalate_cycle_count,
                )

            if raw_cyber_score >= 0.70:
                return self._finalize_restricted_decision(
                    req_id=req_id,
                    reason_codes=["LEGACY_UNCALIBRATED_CYBER_INTENT_HIGH"],
                    reason=f"RESTRICTED — [Legacy Fallback] High uncalibrated cyber intent match ({raw_cyber_score:.2f}).",
                    health_map=health_map,
                    evidence=evidence,
                    escalate_cycle_count=escalate_cycle_count,
                )

            if raw_attack_score >= 0.50 or raw_cyber_score >= 0.50:
                return self._finalize_restricted_decision(
                    req_id=req_id,
                    reason_codes=["MODERATE_RISK_THRESHOLD"],
                    reason="RESTRICTED — Moderate threat threshold met; routing to Air-Gapped Shield.",
                    health_map=health_map,
                    evidence=evidence,
                    escalate_cycle_count=escalate_cycle_count,
                )

            # -----------------------------------------------------------------
            # 9. DEFAULT ALLOW TO APPROVED CLOUD LLM (NORMAL)
            # Note: Shield health is completely irrelevant for NORMAL requests!
            # -----------------------------------------------------------------
            decision = PolicyDecision(
                request_id=req_id,
                route=self.default_route,
                policy_version=self.POLICY_VERSION,
                reason_codes=["POLICY_ALLOW_NORMAL"],
                reason="NORMAL — Evaluated all security rails with zero policy violations.",
                permitted_route="NORMAL",
                permitted_destinations=["cloud.approved.normal"],
                cloud_fallback=False,
                rail_health=health_map,
                evidence=evidence if isinstance(evidence, SecurityEvidence) else None,
                classification_result=evidence,
            )
            decision.sign()
            return decision

        except Exception as exc:
            logger.error("PolicyEngine fatal evaluation error: %s (Failing closed to SHIELD)", exc)
            return self._finalize_restricted_decision(
                req_id=metadata.get("request_id", "req-err") if metadata else "req-err",
                reason_codes=["PDP_EVALUATION_ERROR_FAIL_CLOSED"],
                reason=f"RESTRICTED — PDP evaluation error: {exc} (Fail-Closed to Air-Gapped Shield)",
                health_map=rail_health or {},
                evidence=evidence,
                escalate_cycle_count=escalate_cycle_count,
            )

    def _finalize_restricted_decision(
        self,
        req_id: str,
        reason_codes: list[str],
        reason: str,
        health_map: dict[str, str],
        evidence: Any,
        escalate_cycle_count: int = 0,
    ) -> PolicyDecision:
        """
        Finalize a RESTRICTED decision with execution-constrained Shield health gating.
        If and only if traffic is RESTRICTED, an offline Shield fails closed to UNAVAILABLE/DENY.
        """
        is_shield_down = health_map.get("shield") == RailHealthStatus.UNAVAILABLE.value

        if is_shield_down:
            decision = PolicyDecision(
                request_id=req_id,
                route=Route.UNAVAILABLE,
                policy_version=self.POLICY_VERSION,
                reason_codes=reason_codes + ["SHIELD_HEALTH_UNAVAILABLE"],
                reason=f"UNAVAILABLE — Request requires Shield isolation, but Shield is offline (Fail-Closed): {reason}",
                permitted_route="NONE",
                permitted_destinations=[],
                cloud_fallback=False,
                execution_status="SHIELD_UNAVAILABLE",
                rail_health=health_map,
                evidence=evidence if isinstance(evidence, SecurityEvidence) else None,
                classification_result=evidence,
                escalate_cycle_count=escalate_cycle_count,
            )
        else:
            decision = PolicyDecision(
                request_id=req_id,
                route=Route.SHIELD,
                policy_version=self.POLICY_VERSION,
                reason_codes=reason_codes,
                reason=reason,
                permitted_route="SHIELD",
                permitted_destinations=["shield.internal.local"],
                cloud_fallback=False,
                rail_health=health_map,
                evidence=evidence if isinstance(evidence, SecurityEvidence) else None,
                classification_result=evidence,
                escalate_cycle_count=escalate_cycle_count,
            )

        decision.sign()
        return decision
