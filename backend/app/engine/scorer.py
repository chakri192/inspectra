from typing import List, Dict, Tuple, Optional
from app.config import settings
from app.engine.rules.base import Rule, ThreatCategory
from app.engine.rules.registry import rule_registry
from app.models.responses import Verdict, Severity, Finding, UrlFinding


def calculate_risk_score(
    findings: List[Finding],
    url_findings: List[UrlFinding],
    input_type: str
) -> Tuple[int, str]:
    """
    Computes a heuristic risk score between 0 and 100 based on detected indicators.
    Enforces diminishing returns within signal families to avoid double-counting.
    Ensures that high-risk URLs are never averaged away.
    Returns (risk_score, dominant_category).
    """
    if not findings and not url_findings:
        return 0, "benign"

    # Group findings by signal family
    family_scores: Dict[str, List[int]] = {}
    category_counts: Dict[str, int] = {
        ThreatCategory.PHISHING.value: 0,
        ThreatCategory.DIGITAL_ARREST.value: 0,
        ThreatCategory.APP_INSTALLATION.value: 0,
        ThreatCategory.GENERAL.value: 0,
    }

    for finding in findings:
        rule = rule_registry.get_rule(finding.rule_id)
        if not rule:
            # Fallback based on severity if dynamic finding
            weight = 30 if finding.severity == Severity.HIGH else (50 if finding.severity == Severity.CRITICAL else 15)
            family = "miscellaneous"
            cat = ThreatCategory.GENERAL.value
        elif finding.rule_id == "llama_semantic_detection":
            # Dynamic score based on AI finding severity (15 for Medium, 25 for High)
            weight = 15 if finding.severity == Severity.MEDIUM else rule.score_contribution
            family = rule.signal_family
            cat = rule.category.value
        else:
            weight = rule.score_contribution
            family = rule.signal_family
            cat = rule.category.value

        family_scores.setdefault(family, []).append(weight)
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # Separate text/app signal families from URL signal families to prevent double-counting
    url_signal_families = {
        "url_obfuscation", "brand_spoof", "host_type", "homoglyph",
        "payload", "shortener", "tld", "encoding", "scheme_type"
    }

    text_finding_score = 0
    all_finding_score = 0
    for family, scores in family_scores.items():
        sorted_scores = sorted(scores, reverse=True)
        primary = sorted_scores[0]
        secondary = sum(int(s * 0.20) for s in sorted_scores[1:])
        contribution = primary + secondary
        all_finding_score += contribution
        if family not in url_signal_families:
            text_finding_score += contribution

    # URL scoring logic: Max URL score is preserved (never averaged down)
    url_score = 0
    if url_findings:
        max_single_url_score = max(uf.risk_score for uf in url_findings)
        suspicious_url_count = sum(1 for uf in url_findings if uf.risk_score >= settings.SUSPICIOUS_THRESHOLD)
        # Primary URL risk plus slight penalty for multiple suspicious links
        url_score = max_single_url_score + min(15, (suspicious_url_count - 1) * 5 if suspicious_url_count > 1 else 0)

    # Combine message/app and URL findings without double-counting
    if input_type == "url":
        combined_score = max(url_score, all_finding_score)
    else:
        # In message or app request:
        if text_finding_score > 0 and url_score > 0:
            # Synergy combination between coercive text and suspicious URL
            combined_score = max(text_finding_score, url_score, int(text_finding_score * 0.75 + url_score * 0.55))
        elif url_score > 0:
            combined_score = max(url_score, all_finding_score)
        else:
            combined_score = text_finding_score

    final_score = max(0, min(100, combined_score))

    # Determine dominant threat category
    # If digital arrest indicators are present, check their prominence
    if category_counts[ThreatCategory.DIGITAL_ARREST.value] >= 2 or any(
        f.rule_id == "digital_arrest_composite_pattern" for f in findings
    ):
        dominant_category = ThreatCategory.DIGITAL_ARREST.value
    elif category_counts[ThreatCategory.APP_INSTALLATION.value] >= 1 and input_type == "app_request":
        dominant_category = ThreatCategory.APP_INSTALLATION.value
    elif category_counts[ThreatCategory.PHISHING.value] >= 1 or url_score > 0:
        dominant_category = ThreatCategory.PHISHING.value
    elif any(count > 0 for count in category_counts.values()):
        dominant_category = max(category_counts, key=category_counts.get)
    else:
        dominant_category = "benign"

    return final_score, dominant_category


def determine_verdict(
    risk_score: int,
    findings: List[Finding],
    has_insufficient_input: bool = False,
    has_critical_check_failure: bool = False
) -> Verdict:
    """
    Evaluates final verdict:
    - 'unable_to_assess' when input is insufficient or critical external checks fail on otherwise-clean content.
    - 'suspicious' when concerning indicators are detected or risk score meets threshold (suspicious takes precedence).
    - 'appears_safe' when checks complete cleanly without meaningful suspicious indicators.
    """
    if has_insufficient_input:
        return Verdict.UNABLE_TO_ASSESS

    has_concerning_findings = any(
        f.severity in [Severity.HIGH, Severity.CRITICAL] for f in findings
    )
    is_suspicious = risk_score >= settings.SUSPICIOUS_THRESHOLD or has_concerning_findings

    # Suspicious heuristic evidence takes precedence over external check failures
    if is_suspicious:
        return Verdict.SUSPICIOUS

    if has_critical_check_failure:
        return Verdict.UNABLE_TO_ASSESS

    return Verdict.APPEARS_SAFE


def generate_analysis_summary(
    verdict: Verdict,
    risk_score: int,
    category: str,
    findings: List[Finding],
    url_count: int
) -> str:
    """Generates an objective, concise summary explaining the result."""
    if verdict == Verdict.UNABLE_TO_ASSESS:
        return "The submitted content is insufficient or key checks could not complete to produce a conclusive assessment."

    if verdict == Verdict.APPEARS_SAFE:
        return f"No meaningful suspicious indicators were detected across completed checks (Score: {risk_score}/100)."

    # Verdict is suspicious
    category_labels = {
        ThreatCategory.DIGITAL_ARREST.value: "digital-arrest / authority impersonation scam",
        ThreatCategory.PHISHING.value: "phishing or deceptive content",
        ThreatCategory.APP_INSTALLATION.value: "suspicious app request or dangerous privilege pattern",
        ThreatCategory.GENERAL.value: "suspicious cybersecurity threat",
    }
    cat_label = category_labels.get(category, "suspicious threat")

    high_crit_findings = [f.name for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]
    if high_crit_findings:
        preview = "; ".join(high_crit_findings[:3])
        return f"The submitted content exhibits indicators consistent with a {cat_label}. Key signals detected: {preview}."

    return f"Concerning indicators were detected with a risk score of {risk_score}/100."
