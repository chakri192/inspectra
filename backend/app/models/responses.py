from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    APPEARS_SAFE = "appears_safe"
    SUSPICIOUS = "suspicious"
    UNABLE_TO_ASSESS = "unable_to_assess"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    rule_id: str = Field(..., description="Unique identifier for the detection rule")
    name: str = Field(..., description="Human-readable rule name")
    severity: Severity = Field(..., description="Severity level: low, medium, high, or critical")
    evidence: str = Field(..., description="Excerpt or component from the submitted content")
    explanation: str = Field(..., description="User-facing explanation of the finding")


class UrlFinding(BaseModel):
    raw_url: str = Field(..., description="Submitted URL string (rendered as non-clickable text)")
    domain: str = Field(..., description="Registrable domain")
    hostname: str = Field(..., description="Full parsed hostname")
    is_ip: bool = Field(default=False, description="Whether the host is a raw IP address")
    has_suspicious_tld: bool = Field(default=False, description="Whether the TLD is statistically high risk")
    has_homoglyphs: bool = Field(default=False, description="Whether confusable unicode or punycode is present")
    has_embedded_credentials: bool = Field(default=False, description="Whether credentials or misleading @ syntax exists")
    has_executable_extension: bool = Field(default=False, description="Whether link points to direct executable/APK")
    risk_score: int = Field(default=0, ge=0, le=100, description="Individual URL risk score")
    findings: List[Finding] = Field(default_factory=list, description="Findings specific to this URL")


class AnalyzeResponse(BaseModel):
    verdict: Verdict = Field(..., description="Primary verdict: appears_safe, suspicious, or unable_to_assess")
    risk_score: int = Field(..., ge=0, le=100, description="Heuristic risk score from 0 to 100")
    category: str = Field(..., description="Likely threat category or classification")
    summary: str = Field(..., description="Concise summary of findings")
    findings: List[Finding] = Field(default_factory=list, description="Detailed list of detected indicators")
    urls: List[UrlFinding] = Field(default_factory=list, description="Breakdown of individual analyzed URLs")
    checks: Dict[str, str] = Field(
        ...,
        description="Status of all checks: completed, not_applicable, not_configured, failed, skipped"
    )
    limitations: List[str] = Field(
        default_factory=lambda: [
            "This assessment is based on the submitted content and available checks. It does not guarantee safety or confirm malicious intent.",
            "This assessment does not verify the sender's identity.",
            "The risk score is heuristic, not a probability."
        ],
        description="Mandatory limitations and context regarding the analysis"
    )
    engine_version: str = Field(default="1.0.0", description="Version of the Inspectra analysis engine")


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    engine: str = "inspectra-rules-v1"
