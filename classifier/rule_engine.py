"""
Rule Engine — Pattern-based security rule matching.

Loads security rules from central security_knowledge catalog (or custom path)
and evaluates text input against them using pre-compiled regex patterns.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from classifier.models import RuleDefinition, RuleMatch, RuleType, Severity
from security_knowledge.loader import KnowledgeLoader

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Evaluates text against declarative ingress rules loaded from security_knowledge.
    """

    def __init__(self, rules_dir: str | None = None) -> None:
        self._rules: list[RuleDefinition] = []
        self._compiled_regex: dict[str, list[re.Pattern[str]]] = {}

        if rules_dir and Path(rules_dir).exists():
            self.load_rules_from_dir(rules_dir)
        else:
            self.load_from_bundle()

    @property
    def rules(self) -> list[RuleDefinition]:
        """Return loaded rules."""
        return self._rules

    def load_from_bundle(self) -> None:
        """Load rules directly from the central SecurityKnowledgeBundle."""
        bundle = KnowledgeLoader.get_bundle()
        self._rules = []
        self._compiled_regex = {}

        for r_def in bundle.ingress_rules:
            # Map severity
            sev = Severity.HIGH
            if r_def.severity in ("critical", "high"):
                sev = Severity.HIGH
            elif r_def.severity == "medium":
                sev = Severity.MEDIUM
            elif r_def.severity == "low":
                sev = Severity.LOW

            rule = RuleDefinition(
                name=r_def.name,
                category=r_def.category,
                type=RuleType.REGEX if r_def.type == "regex" else RuleType.KEYWORD,
                severity=sev,
                patterns=r_def.patterns,
                enabled=True,
                source=r_def.source or "security_knowledge",
                version=float(r_def.version) if r_def.version else 1.0,
                description=r_def.description or "",
            )
            self._rules.append(rule)

            compiled = []
            for p in rule.patterns:
                try:
                    compiled.append(re.compile(p, re.IGNORECASE))
                except re.error as e:
                    logger.error("Invalid regex in rule '%s': %s — %s", rule.name, p, e)
            self._compiled_regex[rule.name] = compiled

        logger.info("RuleEngine initialized with %d rules from SecurityKnowledgeBundle.", len(self._rules))

    def load_rules_from_dir(self, rules_dir: str) -> None:
        """Fallback directory loader."""
        rules_path = Path(rules_dir)
        self._rules = []
        self._compiled_regex = {}

        for yaml_file in sorted(rules_path.glob("*.yaml")):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data or "rules" not in data:
                    continue

                for raw_rule in data["rules"]:
                    try:
                        rule = RuleDefinition(**raw_rule)
                        if not rule.enabled:
                            continue
                        self._rules.append(rule)
                        compiled = []
                        for pattern in rule.patterns:
                            compiled.append(re.compile(pattern, re.IGNORECASE))
                        self._compiled_regex[rule.name] = compiled
                    except Exception as e:
                        logger.error("Failed to load rule from %s: %s", yaml_file, e)
            except Exception as e:
                logger.error("Failed to parse YAML file %s: %s", yaml_file, e)

    def evaluate(self, text: str) -> list[RuleMatch]:
        """
        Evaluate text against all loaded rules and return matched rules.
        """
        if not text or not self._rules:
            return []

        matches: list[RuleMatch] = []
        text_lower = text.lower()

        for rule in self._rules:
            if not rule.enabled:
                continue

            if rule.type == RuleType.KEYWORD:
                for pattern in rule.patterns:
                    if pattern.lower() in text_lower:
                        matches.append(
                            RuleMatch(
                                rule_name=rule.name,
                                pattern_matched=pattern,
                                severity=rule.severity,
                                match_type=RuleType.KEYWORD,
                            )
                        )
                        break

            elif rule.type == RuleType.REGEX:
                compiled_patterns = self._compiled_regex.get(rule.name, [])
                for compiled_pat in compiled_patterns:
                    m = compiled_pat.search(text)
                    if m:
                        matches.append(
                            RuleMatch(
                                rule_name=rule.name,
                                pattern_matched=m.group(0),
                                severity=rule.severity,
                                match_type=RuleType.REGEX,
                            )
                        )
                        break

        return matches
