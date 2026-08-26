"""Validated loader for the centralized security knowledge bundle."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


DEFAULT_BUNDLE_DIR = Path(__file__).resolve().parent.parent / "security_knowledge"


class KnowledgeBundleError(RuntimeError):
    """Raised when the security knowledge bundle is missing or invalid."""


@dataclass(frozen=True)
class KnowledgeSource:
    """One validated source declared by the bundle manifest."""

    name: str
    path: Path
    required: bool


class SecurityKnowledgeBundle:
    """Loads, validates, and fingerprints declarative security knowledge."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root else DEFAULT_BUNDLE_DIR
        self.manifest_path = self.root / "manifest.yaml"
        self.manifest = self._read_yaml(self.manifest_path)
        self.version = str(self.manifest.get("version", ""))
        if not self.version:
            raise KnowledgeBundleError("Knowledge manifest must define a version")
        self.sources = self._load_sources()
        self.bundle_hash = self._calculate_hash()

    def _load_sources(self) -> dict[str, KnowledgeSource]:
        raw_sources = self.manifest.get("sources")
        if not isinstance(raw_sources, dict) or not raw_sources:
            raise KnowledgeBundleError("Knowledge manifest must define sources")

        sources: dict[str, KnowledgeSource] = {}
        for name, config in raw_sources.items():
            if not isinstance(config, dict) or not config.get("path"):
                raise KnowledgeBundleError(f"Invalid source declaration: {name}")
            path = (self.root / str(config["path"])).resolve()
            if self.root.resolve() not in path.parents:
                raise KnowledgeBundleError(f"Source escapes bundle root: {name}")
            required = bool(config.get("required", True))
            if required and not path.is_file():
                raise KnowledgeBundleError(f"Required knowledge source is missing: {path}")
            sources[name] = KnowledgeSource(name=name, path=path, required=required)
        return sources

    def source_path(self, name: str) -> Path:
        """Return the validated filesystem path for a named source."""
        try:
            return self.sources[name].path
        except KeyError as exc:
            raise KnowledgeBundleError(f"Unknown knowledge source: {name}") from exc

    def load_yaml(self, name: str) -> dict[str, Any]:
        """Load a YAML object from a manifest source."""
        path = self.source_path(name)
        if not path.exists() and not self.sources[name].required:
            return {}
        return self._read_yaml(path)

    def load_json(self, name: str) -> dict[str, Any]:
        """Load a JSON object from a manifest source."""
        path = self.source_path(name)
        if not path.exists() and not self.sources[name].required:
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KnowledgeBundleError(f"Invalid JSON source {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise KnowledgeBundleError(f"JSON source must contain an object: {path}")
        return data

    def load_regex_entries(self, name: str) -> list[tuple[str, re.Pattern[str]]]:
        """Load and compile entries from a YAML ``patterns`` collection."""
        entries = self.load_yaml(name).get("patterns", [])
        if not isinstance(entries, list):
            raise KnowledgeBundleError(f"Source {name} must define a patterns list")
        seen: set[str] = set()
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("id") or not entry.get("pattern"):
                raise KnowledgeBundleError(f"Invalid pattern entry in {name}")
            entry_id = str(entry["id"])
            if entry_id in seen:
                raise KnowledgeBundleError(f"Duplicate pattern id in {name}: {entry_id}")
            seen.add(entry_id)
            try:
                compiled.append((entry_id, re.compile(str(entry["pattern"]), re.IGNORECASE)))
            except re.error as exc:
                raise KnowledgeBundleError(f"Invalid regex {entry_id}: {exc}") from exc
        return compiled

    def validate(self) -> None:
        """Eagerly validate every known structured source and duplicate identifier."""
        self._validate_lexicon("adversarial_lexicon")
        self._validate_lexicon("benign_lexicon")
        self.load_regex_entries("benign_exclusions")
        self.load_regex_entries("active_override_patterns")
        self.load_regex_entries("context_execution_patterns")
        self.load_regex_entries("dlp_patterns")
        seen_rule_ids: set[str] = set()
        for source_name in ("ingress_default", "ingress_custom"):
            rules = self.load_yaml(source_name).get("rules", [])
            if not isinstance(rules, list):
                raise KnowledgeBundleError(f"Source {source_name} must define a rules list")
            for rule in rules:
                if not isinstance(rule, dict):
                    raise KnowledgeBundleError(f"Invalid rule entry in {source_name}")
                rule_id = str(rule.get("id") or rule.get("name") or "")
                if not rule_id:
                    raise KnowledgeBundleError(f"Rule without id or name in {source_name}")
                if rule_id in seen_rule_ids:
                    raise KnowledgeBundleError(f"Duplicate ingress rule id: {rule_id}")
                seen_rule_ids.add(rule_id)
                patterns = rule.get("patterns")
                if not isinstance(patterns, list) or not patterns:
                    raise KnowledgeBundleError(f"Rule {rule_id} has no patterns")
                if str(rule.get("type")) == "regex":
                    for pattern in patterns:
                        try:
                            re.compile(str(pattern), re.IGNORECASE)
                        except re.error as exc:
                            raise KnowledgeBundleError(
                                f"Invalid ingress regex {rule_id}: {exc}"
                            ) from exc

    def lexicon_texts(self, name: str) -> list[str]:
        """Return validated text entries from a lexical source."""
        return [str(entry["text"]) for entry in self._validate_lexicon(name)]

    def _validate_lexicon(self, name: str) -> list[dict[str, Any]]:
        entries = self.load_json(name).get("entries", [])
        if not isinstance(entries, list) or not entries:
            raise KnowledgeBundleError(f"Lexicon {name} must contain entries")
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("id") or not entry.get("text"):
                raise KnowledgeBundleError(f"Invalid lexicon entry in {name}")
            entry_id = str(entry["id"])
            if entry_id in seen:
                raise KnowledgeBundleError(f"Duplicate lexicon id in {name}: {entry_id}")
            seen.add(entry_id)
        return entries

    def _calculate_hash(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.manifest_path.read_bytes())
        for source in sorted(self.sources.values(), key=lambda item: item.name):
            if source.path.exists():
                digest.update(source.name.encode())
                digest.update(source.path.read_bytes())
        return digest.hexdigest()

    @staticmethod
    def _read_yaml(path: Path) -> dict[str, Any]:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise KnowledgeBundleError(f"Invalid YAML source {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise KnowledgeBundleError(f"YAML source must contain an object: {path}")
        return data
