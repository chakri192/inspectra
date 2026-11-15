from enum import Enum
from typing import Callable, Optional, Any, List
from pydantic import BaseModel
from app.models.responses import Severity, Finding


class ThreatCategory(str, Enum):
    PHISHING = "phishing_and_deceptive_links"
    DIGITAL_ARREST = "digital_arrest_and_authority_impersonation"
    APP_INSTALLATION = "suspicious_app_installation"
    GENERAL = "general_suspicious"


class Rule(BaseModel):
    rule_id: str
    name: str
    category: ThreatCategory
    severity: Severity
    score_contribution: int
    user_explanation: str
    signal_family: str  # Used to group related indicators and avoid double-counting

    def create_finding(self, evidence: str, custom_explanation: Optional[str] = None) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            evidence=evidence,
            explanation=custom_explanation or self.user_explanation
        )
