"""
Rule Engine — Pattern-based security rule matching.

Loads security rules from YAML files and evaluates text input against them
using keyword matching and regex patterns. (PRD §6.3)

Rules are kept external to the code, version-controlled, and hot-reloadable.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

from classifier.models import RuleDefinition, RuleMatch, RuleType

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Loads security rules from YAML files and evaluates text against them.

    Supports two match types:
    - keyword: Case-insensitive substring matching
    - regex: Pre-compiled regular expression matching
    """

    def __init__(self, rules_dir: str | None = None) -> None:
        self._rules: list[RuleDefinition] = []
        self._compiled_regex: dict[str, list[re.Pattern[str]]] = {}
        if rules_dir:
            self.load_rules(rules_dir)

    @property
    def rules(self) -> list[RuleDefinition]:
        """Return loaded rules."""
        return self._rules

    def load_rules(self, rules_dir: str) -> None:
        """
        Load all YAML rule files from the specified directory.

        Each YAML file should contain a 'rules' key with a list of rule definitions.
        Rules are validated via Pydantic and compiled regex patterns are cached.
        """
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.warning("Rules directory does not exist: %s", rules_dir)
            return

        self._rules = []
        self._compiled_regex = {}

        for yaml_file in sorted(rules_path.glob("*.yaml")):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data or "rules" not in data:
                    continue

                raw_rules = data["rules"]
                if not isinstance(raw_rules, list):
                    continue

                for raw_rule in raw_rules:
                    try:
                        rule = RuleDefinition(**raw_rule)
                        if not rule.enabled:
                            continue
                        self._rules.append(rule)

                        # Pre-compile regex patterns
                        if rule.type == RuleType.REGEX:
                            compiled = []
                            for pattern in rule.patterns:
                                try:
                                    compiled.append(re.compile(pattern, re.IGNORECASE))
                                except re.error as e:
                                    logger.error(
                                        "Invalid regex in rule '%s': %s — %s",
                                        rule.name, pattern, e,
                                    )
                            self._compiled_regex[rule.name] = compiled

                    except Exception as e:
                        logger.error("Failed to load rule from %s: %s", yaml_file, e)

                logger.info("Loaded %d rules from %s", len(raw_rules), yaml_file.name)

            except Exception as e:
                logger.error("Failed to parse YAML file %s: %s", yaml_file, e)

        logger.info("Total rules loaded: %d", len(self._rules))

    def evaluate(self, text: str) -> list[RuleMatch]:
        """
        Evaluate text against all loaded rules.

        Returns a list of RuleMatch objects for each rule that matched.
        """
        if not text or not text.strip():
            return []

        matches: list[RuleMatch] = []
        text_lower = text.lower()

        for rule in self._rules:
            match = self._evaluate_rule(rule, text, text_lower)
            if match:
                matches.append(match)

        return matches

    def _evaluate_rule(
        self,
        rule: RuleDefinition,
        text: str,
        text_lower: str,
    ) -> RuleMatch | None:
        """Evaluate a single rule against the text."""
        if rule.type == RuleType.KEYWORD:
            return self._match_keywords(rule, text_lower)
        elif rule.type == RuleType.REGEX:
            return self._match_regex(rule, text)
        return None

    INQUIRY_PREFIX = re.compile(
        r'(?i)^\s*(?:classify\s+(?:this|sentence)|evaluate\s+(?:if|whether)|the\s+article\s+says|'
        r'what\s+does|what\s+is|why\s+is|explain\s+why|explain\s+what|explain\s+how|'
        r'اشرح\s+(?:مفهوم|لي\s+ما\s+معنى|ما\s+هو)|قيّم\s+إن|قيم\s+ان|هل\s+عبارة|اكتب\s+policy)\b'
    )

    def _is_quoted_inquiry(self, text: str, matched_span: tuple[int, int]) -> bool:
        """Check if matched pattern is enclosed in quotes within an inquiry/educational context."""
        if not self.INQUIRY_PREFIX.search(text):
            return False
        # Check if matched pattern is within quotes or educational clause
        start, end = matched_span
        preceding = text[:start]
        succeeding = text[end:]
        has_open_quote = ('"' in preceding or "'" in preceding or "«" in preceding or "“" in preceding)
        has_close_quote = ('"' in succeeding or "'" in succeeding or "»" in succeeding or "”" in succeeding)
        if has_open_quote and has_close_quote:
            return True
        if text.strip().lower().startswith(("explain what", "explain how", "explain why", "how do", "ما هو", "اشرح مفهوم", "اشرح لي ما معنى", "اكتب policy")):
            return True
        return False

    def _match_keywords(
        self,
        rule: RuleDefinition,
        text_lower: str,
    ) -> RuleMatch | None:
        """Case-insensitive substring matching."""
        for pattern in rule.patterns:
            pat_lower = pattern.lower()
            idx = text_lower.find(pat_lower)
            if idx != -1:
                if self._is_quoted_inquiry(text_lower, (idx, idx + len(pat_lower))):
                    continue
                return RuleMatch(
                    rule_name=rule.name,
                    pattern_matched=pattern,
                    severity=rule.severity,
                    match_type=RuleType.KEYWORD,
                )
        return None

    def _match_regex(
        self,
        rule: RuleDefinition,
        text: str,
    ) -> RuleMatch | None:
        """Pre-compiled regex pattern matching."""
        compiled_patterns = self._compiled_regex.get(rule.name, [])
        for pattern in compiled_patterns:
            match = pattern.search(text)
            if match:
                if self._is_quoted_inquiry(text, match.span()):
                    continue
                return RuleMatch(
                    rule_name=rule.name,
                    pattern_matched=match.group(0),
                    severity=rule.severity,
                    match_type=RuleType.REGEX,
                )
        return None

    def reload(self, rules_dir: str) -> None:
        """Hot-reload rules from disk."""
        logger.info("Reloading rules from %s", rules_dir)
        self.load_rules(rules_dir)
