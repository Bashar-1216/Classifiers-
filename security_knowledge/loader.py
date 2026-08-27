"""
Security Knowledge Loader & Manifest Verifier.

Central loader responsible for:
1. Parsing 'manifest.yaml' catalog and bundle integrity.
2. Ingesting, schema-validating, and pre-compiling all declarative security rules,
   lexicons, exclusions, probing terms, DLP patterns, and semantic anchors.
3. Validating unique IDs and preventing duplicate/invalid regexes at startup.
4. Calculating bundle SHA-256 hash for audit telemetry and zero-trust verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

SECURITY_KNOWLEDGE_DIR = Path(__file__).resolve().parent


class PatternEntry(BaseModel):
    id: str
    description: Optional[str] = None
    pattern: Optional[str] = None
    patterns: Optional[List[str]] = None
    validation: Optional[str] = None
    category: Optional[str] = None
    confidence: Optional[float] = None
    prefix: Optional[str] = None


class RuleDefinition(BaseModel):
    id: Optional[str] = None
    name: str
    category: str
    type: str = "regex"
    severity: str = "high"
    source: Optional[str] = None
    version: Optional[float | str] = None
    description: Optional[str] = None
    patterns: List[str] = Field(default_factory=list)


class SecurityKnowledgeBundle:
    """Loaded, validated, and pre-compiled security knowledge bundle."""

    def __init__(
        self,
        bundle_hash: str,
        ingress_rules: List[RuleDefinition],
        adversarial_lexicon: List[str],
        benign_lexicon: List[str],
        benign_exclusions: List[re.Pattern],
        active_overrides: List[re.Pattern],
        context_probing_terms: List[str],
        context_execution_regexes: List[re.Pattern],
        pii_dlp_patterns: List[Dict[str, Any]],
        secret_dlp_patterns: List[Dict[str, Any]],
        semantic_anchors: Dict[str, List[str]],
        adversarial_sequences: List[List[str]] | None = None,
        override_vocabulary: List[str] | None = None,
        metadata_modifiers: Dict[str, Any] | None = None,
        inquiry_prefixes: tuple[str, ...] | None = None,
        quoted_inquiry_markers: tuple[str, ...] | None = None,
        morphological_roots: List[str] | None = None,
        obfuscation_patterns: Dict[str, Any] | None = None,
        multi_turn_rules: Dict[str, Any] | None = None,
    ) -> None:
        self.bundle_hash = bundle_hash
        self.ingress_rules = ingress_rules
        self.adversarial_lexicon = adversarial_lexicon
        self.benign_lexicon = benign_lexicon
        self.benign_exclusions = benign_exclusions
        self.active_overrides = active_overrides
        self.context_probing_terms = context_probing_terms
        self.context_execution_regexes = context_execution_regexes
        self.pii_dlp_patterns = pii_dlp_patterns
        self.secret_dlp_patterns = secret_dlp_patterns
        self.semantic_anchors = semantic_anchors
        self.adversarial_sequences = adversarial_sequences or []
        self.override_vocabulary = override_vocabulary or []
        self.metadata_modifiers = metadata_modifiers or {}
        self.inquiry_prefixes = inquiry_prefixes or ()
        self.quoted_inquiry_markers = quoted_inquiry_markers or ()
        self.morphological_roots = morphological_roots or []
        self.obfuscation_patterns = obfuscation_patterns or {}
        self.multi_turn_rules = multi_turn_rules or {}


class KnowledgeLoader:
    """
    Singleton Loader for Security Knowledge.
    Loads once at startup with strict fail-fast validation.
    """

    _instance: Optional[KnowledgeLoader] = None
    _bundle: Optional[SecurityKnowledgeBundle] = None

    def __init__(self, root_dir: Optional[Path] = None) -> None:
        self.root_dir = root_dir or SECURITY_KNOWLEDGE_DIR
        self.manifest_path = self.root_dir / "manifest.yaml"
        self._bundle = self._load_and_validate()

    @classmethod
    def get_bundle(cls, root_dir: Optional[Path] = None) -> SecurityKnowledgeBundle:
        """Get or initialize the loaded SecurityKnowledgeBundle."""
        if cls._instance is None:
            cls._instance = cls(root_dir)
        return cls._instance._bundle  # type: ignore[return-value]

    def _compute_file_hash(self, path: Path) -> str:
        if not path.exists():
            return "missing"
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _load_and_validate(self) -> SecurityKnowledgeBundle:
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Security manifest not found at: {self.manifest_path}")

        manifest_content = yaml.safe_load(self.manifest_path.read_text(encoding="utf-8"))
        sources = manifest_content.get("sources", {})

        all_hashes = [self._compute_file_hash(self.manifest_path)]
        seen_ids: Set[str] = set()

        # 1. Load Rules (Default + Custom + Output Policy + Safety Rules)
        ingress_rules: List[RuleDefinition] = []
        for src_key in ["ingress_default", "ingress_custom", "output_policy", "safety_rules"]:
            src_info = sources.get(src_key)
            if not src_info:
                continue
            src_path = self.root_dir / src_info["path"]
            if not src_path.exists():
                if src_info.get("required", False):
                    raise FileNotFoundError(f"Required rule file missing: {src_path}")
                continue

            all_hashes.append(self._compute_file_hash(src_path))
            raw_rules = yaml.safe_load(src_path.read_text(encoding="utf-8"))
            if raw_rules and "rules" in raw_rules:
                for r in raw_rules["rules"]:
                    rule_id = r.get("id") or r.get("name")
                    if rule_id in seen_ids:
                        raise ValueError(f"Duplicate Rule ID detected: {rule_id}")
                    seen_ids.add(rule_id)
                    # Validate regexes
                    for p in r.get("patterns", []):
                        try:
                            re.compile(p)
                        except re.error as e:
                            raise ValueError(f"Invalid regex in rule {rule_id}: {p} -> {e}")
                    ingress_rules.append(RuleDefinition(**r))

        # 2. Load Lexicons
        adversarial_lexicon: List[str] = []
        adv_info = sources.get("adversarial_lexicon", {})
        adv_path = self.root_dir / adv_info.get("path", "lexicons/adversarial.json")
        if adv_path.exists():
            all_hashes.append(self._compute_file_hash(adv_path))
            adv_data = json.loads(adv_path.read_text(encoding="utf-8"))
            for entry in adv_data.get("entries", []):
                e_id = entry.get("id")
                if e_id:
                    if e_id in seen_ids:
                        raise ValueError(f"Duplicate Lexicon ID: {e_id}")
                    seen_ids.add(e_id)
                adversarial_lexicon.append(entry["text"])

        benign_lexicon: List[str] = []
        ben_info = sources.get("benign_lexicon", {})
        ben_path = self.root_dir / ben_info.get("path", "lexicons/benign.json")
        if ben_path.exists():
            all_hashes.append(self._compute_file_hash(ben_path))
            ben_data = json.loads(ben_path.read_text(encoding="utf-8"))
            for entry in ben_data.get("entries", []):
                e_id = entry.get("id")
                if e_id:
                    if e_id in seen_ids:
                        raise ValueError(f"Duplicate Lexicon ID: {e_id}")
                    seen_ids.add(e_id)
                benign_lexicon.append(entry["text"])

        # 3. Load Exclusions & Active Overrides
        benign_exclusions: List[re.Pattern] = []
        excl_info = sources.get("benign_exclusions", {})
        excl_path = self.root_dir / excl_info.get("path", "exclusions/benign.yaml")
        if excl_path.exists():
            all_hashes.append(self._compute_file_hash(excl_path))
            excl_data = yaml.safe_load(excl_path.read_text(encoding="utf-8"))
            for item in excl_data.get("exclusions", []):
                p_id = item.get("id")
                if p_id in seen_ids:
                    raise ValueError(f"Duplicate Exclusion ID: {p_id}")
                seen_ids.add(p_id)
                for pat in item.get("patterns", []):
                    try:
                        benign_exclusions.append(re.compile(pat))
                    except re.error as e:
                        raise ValueError(f"Invalid exclusion pattern in {p_id}: {pat} -> {e}")

        active_overrides: List[re.Pattern] = []
        ovr_info = sources.get("active_overrides", {})
        ovr_path = self.root_dir / ovr_info.get("path", "exclusions/active_overrides.yaml")
        if ovr_path.exists():
            all_hashes.append(self._compute_file_hash(ovr_path))
            ovr_data = yaml.safe_load(ovr_path.read_text(encoding="utf-8"))
            for item in ovr_data.get("patterns", []):
                p_id = item.get("id")
                if p_id in seen_ids:
                    raise ValueError(f"Duplicate Override ID: {p_id}")
                seen_ids.add(p_id)
                pat = item.get("pattern")
                if pat:
                    try:
                        active_overrides.append(re.compile(pat))
                    except re.error as e:
                        raise ValueError(f"Invalid active override pattern in {p_id}: {pat} -> {e}")

        # 4. Load Context Probing & Execution
        context_probing_terms: List[str] = []
        ctx_p_info = sources.get("context_probing", {})
        ctx_p_path = self.root_dir / ctx_p_info.get("path", "context/probing_terms.json")
        if ctx_p_path.exists():
            all_hashes.append(self._compute_file_hash(ctx_p_path))
            ctx_p_data = json.loads(ctx_p_path.read_text(encoding="utf-8"))
            for lang, terms in ctx_p_data.get("languages", {}).items():
                context_probing_terms.extend(terms)

        context_execution_regexes: List[re.Pattern] = []
        ctx_e_info = sources.get("context_execution", {})
        ctx_e_path = self.root_dir / ctx_e_info.get("path", "context/execution_patterns.yaml")
        if ctx_e_path.exists():
            all_hashes.append(self._compute_file_hash(ctx_e_path))
            ctx_e_data = yaml.safe_load(ctx_e_path.read_text(encoding="utf-8"))
            for item in ctx_e_data.get("patterns", []):
                p_id = item.get("id")
                if p_id in seen_ids:
                    raise ValueError(f"Duplicate Context Execution ID: {p_id}")
                seen_ids.add(p_id)
                pat = item.get("pattern")
                if pat:
                    try:
                        context_execution_regexes.append(re.compile(pat))
                    except re.error as e:
                        raise ValueError(f"Invalid context execution pattern in {p_id}: {pat} -> {e}")

        # 5. Load DLP Patterns (PII & Secrets)
        pii_dlp_patterns: List[Dict[str, Any]] = []
        pii_info = sources.get("dlp_pii", {})
        pii_path = self.root_dir / pii_info.get("path", "dlp/pii_patterns.yaml")
        if pii_path.exists():
            all_hashes.append(self._compute_file_hash(pii_path))
            pii_data = yaml.safe_load(pii_path.read_text(encoding="utf-8"))
            for item in pii_data.get("patterns", []):
                p_id = item.get("id")
                if p_id in seen_ids:
                    raise ValueError(f"Duplicate PII ID: {p_id}")
                seen_ids.add(p_id)
                raw_pats = item.get("patterns", [])
                if item.get("pattern"):
                    raw_pats.append(item["pattern"])
                item["compiled_patterns"] = [re.compile(p) for p in raw_pats]
                pii_dlp_patterns.append(item)

        secret_dlp_patterns: List[Dict[str, Any]] = []
        sec_info = sources.get("dlp_secrets", {})
        sec_path = self.root_dir / sec_info.get("path", "dlp/secret_patterns.yaml")
        if sec_path.exists():
            all_hashes.append(self._compute_file_hash(sec_path))
            sec_data = yaml.safe_load(sec_path.read_text(encoding="utf-8"))
            for item in sec_data.get("patterns", []):
                p_id = item.get("id")
                if p_id in seen_ids:
                    raise ValueError(f"Duplicate Secret ID: {p_id}")
                seen_ids.add(p_id)
                raw_pats = item.get("patterns", [])
                if item.get("pattern"):
                    raw_pats.append(item["pattern"])
                item["compiled_patterns"] = [re.compile(p) for p in raw_pats]
                secret_dlp_patterns.append(item)

        # 6. Load Semantic Anchors
        semantic_anchors: Dict[str, List[str]] = {}
        sem_info = sources.get("semantic_anchors", {})
        sem_path = self.root_dir / sem_info.get("path", "semantic/risk_anchors.json")
        if sem_path.exists():
            all_hashes.append(self._compute_file_hash(sem_path))
            sem_data = json.loads(sem_path.read_text(encoding="utf-8"))
            semantic_anchors = sem_data.get("clusters", {})

        # 7. Load Adversarial Sequences & Override Vocab
        adversarial_sequences: List[List[str]] = []
        override_vocabulary: List[str] = []
        seq_info = sources.get("adversarial_sequences", {})
        seq_path = self.root_dir / seq_info.get("path", "sequences/adversarial_flows.yaml")
        if seq_path.exists():
            all_hashes.append(self._compute_file_hash(seq_path))
            seq_data = yaml.safe_load(seq_path.read_text(encoding="utf-8")) or {}
            adversarial_sequences = seq_data.get("adversarial_sequences", [])
            override_vocabulary = seq_data.get("override_vocabulary", [])

        # 8. Load Metadata Risk Modifiers
        metadata_modifiers: Dict[str, Any] = {}
        meta_info = sources.get("metadata_modifiers", {})
        meta_path = self.root_dir / meta_info.get("path", "metadata/risk_modifiers.yaml")
        if meta_path.exists():
            all_hashes.append(self._compute_file_hash(meta_path))
            metadata_modifiers = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}

        # 9. Load Inquiry Prefixes & Quoted Markers
        inquiry_prefixes_tuple: tuple[str, ...] = ()
        quoted_inquiry_markers_tuple: tuple[str, ...] = ()
        inq_info = sources.get("inquiry_prefixes", {})
        inq_path = self.root_dir / inq_info.get("path", "exclusions/inquiry_prefixes.json")
        if inq_path.exists():
            all_hashes.append(self._compute_file_hash(inq_path))
            inq_data = json.loads(inq_path.read_text(encoding="utf-8")) or {}
            inquiry_prefixes_tuple = tuple(inq_data.get("inquiry_prefixes", []))
            quoted_inquiry_markers_tuple = tuple(inq_data.get("quoted_inquiry_markers", []))

        # 10. Load Morphological Roots
        morphological_roots: List[str] = []
        root_info = sources.get("morphological_roots", {})
        root_path = self.root_dir / root_info.get("path", "lexicons/morphological_roots.json")
        if root_path.exists():
            all_hashes.append(self._compute_file_hash(root_path))
            root_data = json.loads(root_path.read_text(encoding="utf-8")) or {}
            morphological_roots = root_data.get("morphological_roots", [])

        # 11. Load Obfuscation Patterns
        obfuscation_patterns: Dict[str, Any] = {}
        obf_info = sources.get("obfuscation_patterns", {})
        obf_path = self.root_dir / obf_info.get("path", "statistical/obfuscation_patterns.yaml")
        if obf_path.exists():
            all_hashes.append(self._compute_file_hash(obf_path))
            obfuscation_patterns = yaml.safe_load(obf_path.read_text(encoding="utf-8")) or {}

        # 12. Load Multi-Turn Context Rules
        multi_turn_rules: Dict[str, Any] = {}
        mt_info = sources.get("multi_turn_rules", {})
        mt_path = self.root_dir / mt_info.get("path", "context/multi_turn_rules.yaml")
        if mt_path.exists():
            all_hashes.append(self._compute_file_hash(mt_path))
            multi_turn_rules = yaml.safe_load(mt_path.read_text(encoding="utf-8")) or {}

        # Compute Bundle Hash
        bundle_hash = hashlib.sha256("".join(all_hashes).encode("utf-8")).hexdigest()[:16]

        logger.info(
            "Security Knowledge Bundle loaded successfully (Hash=%s, Rules=%d, Lexicons=%d, Exclusions=%d, DLP=%d).",
            bundle_hash,
            len(ingress_rules),
            len(adversarial_lexicon) + len(benign_lexicon),
            len(benign_exclusions),
            len(pii_dlp_patterns) + len(secret_dlp_patterns),
        )

        return SecurityKnowledgeBundle(
            bundle_hash=bundle_hash,
            ingress_rules=ingress_rules,
            adversarial_lexicon=adversarial_lexicon,
            benign_lexicon=benign_lexicon,
            benign_exclusions=benign_exclusions,
            active_overrides=active_overrides,
            context_probing_terms=context_probing_terms,
            context_execution_regexes=context_execution_regexes,
            pii_dlp_patterns=pii_dlp_patterns,
            secret_dlp_patterns=secret_dlp_patterns,
            semantic_anchors=semantic_anchors,
            adversarial_sequences=adversarial_sequences,
            override_vocabulary=override_vocabulary,
            metadata_modifiers=metadata_modifiers,
            inquiry_prefixes=inquiry_prefixes_tuple,
            quoted_inquiry_markers=quoted_inquiry_markers_tuple,
            morphological_roots=morphological_roots,
            obfuscation_patterns=obfuscation_patterns,
            multi_turn_rules=multi_turn_rules,
        )
