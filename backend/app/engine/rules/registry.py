from typing import Dict, List, Optional
from app.engine.rules.base import Rule, ThreatCategory, Severity
from app.engine.rules.message_rules import MESSAGE_RULES
from app.engine.rules.url_rules import URL_RULES
from app.engine.rules.app_rules import APP_RULES

RULE_LLAMA_SEMANTIC = Rule(
    rule_id="llama_semantic_detection",
    name="AI Semantic Threat Verification (LLaMA)",
    category=ThreatCategory.GENERAL,
    severity=Severity.HIGH,
    score_contribution=25,
    user_explanation="An AI semantic model verified coercive social engineering or deceptive threat patterns in the content.",
    signal_family="ai_semantic"
)


class RuleRegistry:
    """
    Central repository of all security rules in Inspectra.
    Enforces uniqueness of rule IDs and provides convenient lookup utilities.
    """

    def __init__(self):
        self._rules: Dict[str, Rule] = {}
        self._load_rules()

    def _load_rules(self):
        all_rules: List[Rule] = MESSAGE_RULES + URL_RULES + APP_RULES + [RULE_LLAMA_SEMANTIC]
        for rule in all_rules:
            if rule.rule_id in self._rules:
                raise ValueError(f"Duplicate Rule ID detected: {rule.rule_id}")
            self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        return self._rules.get(rule_id)

    def get_rules_by_category(self, category: ThreatCategory) -> List[Rule]:
        return [r for r in self._rules.values() if r.category == category]

    def list_all_rules(self) -> List[Rule]:
        return list(self._rules.values())

    @property
    def total_count(self) -> int:
        return len(self._rules)


# Global rule registry singleton
rule_registry = RuleRegistry()
