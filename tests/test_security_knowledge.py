"""Validation and integration tests for the centralized security knowledge bundle."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from classifier.knowledge_loader import KnowledgeBundleError, SecurityKnowledgeBundle
from classifier.lexical_engine import LexicalSignalEngine
from classifier.local_adjudicator import LocalRiskAdjudicator
from classifier.context_analyzer import ContextAnalyzer
from risk_engine.specialized.dlp_validator import DLPValidator


def test_default_bundle_is_complete_and_valid() -> None:
    bundle = SecurityKnowledgeBundle()

    bundle.validate()

    assert bundle.version == "1.0.0"
    assert len(bundle.bundle_hash) == 64
    assert bundle.source_path("semantic_anchors").is_file()


def test_engines_consume_centralized_sources() -> None:
    bundle = SecurityKnowledgeBundle()

    lexical = LexicalSignalEngine(bundle)
    adjudicator = LocalRiskAdjudicator(bundle)
    context = ContextAnalyzer(knowledge_bundle=bundle)
    dlp = DLPValidator(bundle)

    assert lexical.adv_bm25.corpus
    assert adjudicator.exclusion_regexes
    assert "اختراق" in context.probing_terms
    assert dlp.patterns


def test_dlp_patterns_keep_validation_in_python() -> None:
    validator = DLPValidator(SecurityKnowledgeBundle())

    assert validator.evaluate("Card: 4000 0000 0000 0002") == {
        "dlp_confirmed_credit_card": 1.0
    }
    assert validator.evaluate("Card: 4000 0000 0000 0003") == {}


def test_duplicate_lexicon_ids_fail_validation(tmp_path: Path) -> None:
    bundle_root = _minimal_bundle(tmp_path)
    lexicon_path = bundle_root / "lexical" / "adversarial.json"
    lexicon_path.write_text(
        json.dumps(
            {
                "entries": [
                    {"id": "DUP", "text": "one"},
                    {"id": "DUP", "text": "two"},
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(KnowledgeBundleError, match="Duplicate lexicon id"):
        SecurityKnowledgeBundle(bundle_root).validate()


def test_invalid_regex_fails_validation(tmp_path: Path) -> None:
    bundle_root = _minimal_bundle(tmp_path)
    exclusions = bundle_root / "adjudication" / "benign_exclusions.yaml"
    exclusions.write_text(
        yaml.safe_dump({"patterns": [{"id": "BAD", "pattern": "["}]}),
        encoding="utf-8",
    )

    with pytest.raises(KnowledgeBundleError, match="Invalid regex"):
        SecurityKnowledgeBundle(bundle_root).validate()


def test_duplicate_ingress_rule_ids_fail_validation(tmp_path: Path) -> None:
    bundle_root = _minimal_bundle(tmp_path)
    custom_rules = bundle_root / "ingress" / "custom_rules.yaml"
    custom_rules.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "SEC-RULE-001",
                        "name": "duplicate",
                        "type": "keyword",
                        "severity": "high",
                        "patterns": ["duplicate"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(KnowledgeBundleError, match="Duplicate ingress rule id"):
        SecurityKnowledgeBundle(bundle_root).validate()


def _minimal_bundle(tmp_path: Path) -> Path:
    source = SecurityKnowledgeBundle().root
    destination = tmp_path / "security_knowledge"
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    return destination
