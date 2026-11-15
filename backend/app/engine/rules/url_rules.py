import re
from typing import List, Tuple
from app.engine.rules.base import Rule, ThreatCategory
from app.models.responses import Severity, Finding, UrlFinding
from app.engine.url_parser import ParsedUrl, parse_url_string


RULE_EMBEDDED_CREDENTIALS = Rule(
    rule_id="url_embedded_credentials",
    name="Misleading Credentials or '@' Symbol in URL Authority",
    category=ThreatCategory.PHISHING,
    severity=Severity.CRITICAL,
    score_contribution=45,
    user_explanation="The URL uses '@' syntax to mislead the user into seeing a trusted domain before the actual destination host.",
    signal_family="url_obfuscation"
)

RULE_MISLEADING_SUBDOMAIN = Rule(
    rule_id="url_misleading_subdomain",
    name="Deceptive Brand Impersonation in Subdomain",
    category=ThreatCategory.PHISHING,
    severity=Severity.HIGH,
    score_contribution=40,
    user_explanation="A recognized brand name appears as a subdomain prefix, but the root domain belongs to an unrelated entity.",
    signal_family="brand_spoof"
)

RULE_IP_HOST = Rule(
    rule_id="url_raw_ip_host",
    name="Direct IP Address Hostname",
    category=ThreatCategory.PHISHING,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The link connects directly to a numerical IP address rather than a registered domain name, common in malicious or unverified infrastructure.",
    signal_family="host_type"
)

RULE_HOMOGLYPH_DOMAIN = Rule(
    rule_id="url_homoglyph_punycode",
    name="Lookalike Homoglyph or Punycode Characters",
    category=ThreatCategory.PHISHING,
    severity=Severity.HIGH,
    score_contribution=40,
    user_explanation="The domain uses visually deceptive non-ASCII characters or Punycode (xn--) to mimic a legitimate domain name.",
    signal_family="homoglyph"
)

RULE_EXECUTABLE_DOWNLOAD = Rule(
    rule_id="url_direct_executable_download",
    name="Direct App or Executable File Download Link",
    category=ThreatCategory.APP_INSTALLATION,
    severity=Severity.HIGH,
    score_contribution=40,
    user_explanation="The URL directly downloads an executable or mobile application package (.apk, .exe, .scr, etc.).",
    signal_family="payload"
)

RULE_SHORTENER_LINK = Rule(
    rule_id="url_shortened_destination",
    name="URL Shortener Masking Actual Destination",
    category=ThreatCategory.PHISHING,
    severity=Severity.LOW,
    score_contribution=15,
    user_explanation="The link uses a URL shortening service that conceals the true destination hostname and path.",
    signal_family="shortener"
)

RULE_SUSPICIOUS_TLD = Rule(
    rule_id="url_suspicious_tld",
    name="High-Risk or Abused Top-Level Domain (TLD)",
    category=ThreatCategory.PHISHING,
    severity=Severity.MEDIUM,
    score_contribution=20,
    user_explanation="The domain uses a TLD that is statistically prevalent in disposable phishing and malicious campaigns.",
    signal_family="tld"
)

RULE_SUSPICIOUS_ENCODING = Rule(
    rule_id="url_suspicious_encoding",
    name="Obfuscated or Double-URL Encoded Path",
    category=ThreatCategory.PHISHING,
    severity=Severity.MEDIUM,
    score_contribution=25,
    user_explanation="The URL contains double-encoded characters (%25...) designed to evade security inspection filters.",
    signal_family="encoding"
)

RULE_DANGEROUS_SCHEME = Rule(
    rule_id="url_dangerous_scheme",
    name="Dangerous or Executable URI Scheme",
    category=ThreatCategory.PHISHING,
    severity=Severity.CRITICAL,
    score_contribution=60,
    user_explanation="The link uses an executable or unsupported pseudo-scheme (e.g., javascript:, data:, file:) that can execute code directly in a browser.",
    signal_family="scheme_type"
)

URL_RULES = [
    RULE_DANGEROUS_SCHEME,
    RULE_EMBEDDED_CREDENTIALS,
    RULE_MISLEADING_SUBDOMAIN,
    RULE_IP_HOST,
    RULE_HOMOGLYPH_DOMAIN,
    RULE_EXECUTABLE_DOWNLOAD,
    RULE_SHORTENER_LINK,
    RULE_SUSPICIOUS_TLD,
    RULE_SUSPICIOUS_ENCODING,
]


def analyze_parsed_url(parsed: ParsedUrl) -> Tuple[List[Finding], int]:
    """
    Evaluates a single parsed URL and returns findings and calculated URL risk score.
    """
    findings: List[Finding] = []
    score = 0

    # 0. Dangerous scheme
    if parsed.is_dangerous_scheme:
        evidence = f"Dangerous URI scheme '{parsed.dangerous_scheme_name}:'"
        findings.append(RULE_DANGEROUS_SCHEME.create_finding(evidence))
        score += RULE_DANGEROUS_SCHEME.score_contribution
        return findings, min(100, score)

    # 1. Embedded credentials / @ symbol
    if parsed.has_embedded_credentials:
        evidence = f"Authority userinfo: '{parsed.userinfo}@' before host '{parsed.hostname}'"
        findings.append(RULE_EMBEDDED_CREDENTIALS.create_finding(evidence))
        score += RULE_EMBEDDED_CREDENTIALS.score_contribution

    # 2. Misleading subdomain
    if parsed.misleading_subdomain:
        evidence = f"Subdomain '{parsed.subdomain}' impersonates brand '{parsed.impersonated_brand}' on unrelated root domain '{parsed.registrable_domain}'"
        findings.append(RULE_MISLEADING_SUBDOMAIN.create_finding(evidence))
        score += RULE_MISLEADING_SUBDOMAIN.score_contribution

    # 3. IP address host
    if parsed.is_ip:
        evidence = f"Hostname is raw IP: '{parsed.hostname}'"
        findings.append(RULE_IP_HOST.create_finding(evidence))
        score += RULE_IP_HOST.score_contribution

    # 4. Homoglyphs / Punycode
    if parsed.has_homoglyphs:
        evidence = f"Hostname '{parsed.hostname}': {parsed.homoglyph_details}"
        findings.append(RULE_HOMOGLYPH_DOMAIN.create_finding(evidence))
        score += RULE_HOMOGLYPH_DOMAIN.score_contribution

    # 5. Executable / APK file download
    if parsed.has_executable_extension:
        evidence = f"URL path '{parsed.path}' points to executable extension '{parsed.executable_ext}'"
        findings.append(RULE_EXECUTABLE_DOWNLOAD.create_finding(evidence))
        score += RULE_EXECUTABLE_DOWNLOAD.score_contribution

    # 6. Shortener link
    if parsed.is_shortener:
        evidence = f"Known shortener domain: '{parsed.registrable_domain}'"
        findings.append(RULE_SHORTENER_LINK.create_finding(evidence))
        score += RULE_SHORTENER_LINK.score_contribution

    # 7. Suspicious TLD
    if parsed.has_suspicious_tld:
        evidence = f"Domain suffix '.{parsed.suffix}' is a high-risk TLD"
        findings.append(RULE_SUSPICIOUS_TLD.create_finding(evidence))
        score += RULE_SUSPICIOUS_TLD.score_contribution

    # 8. Suspicious encoding
    if parsed.has_suspicious_encoding:
        evidence = f"Double URL-encoded sequence in: '{parsed.raw_url}'"
        findings.append(RULE_SUSPICIOUS_ENCODING.create_finding(evidence))
        score += RULE_SUSPICIOUS_ENCODING.score_contribution

    # Cap individual URL score at 100
    capped_score = min(100, score)
    return findings, capped_score


def build_url_finding_summary(parsed: ParsedUrl, findings: List[Finding], score: int) -> UrlFinding:
    """Creates a clean API-compliant UrlFinding representation."""
    return UrlFinding(
        raw_url=parsed.raw_url,
        domain=parsed.registrable_domain,
        hostname=parsed.hostname,
        is_ip=parsed.is_ip,
        has_suspicious_tld=parsed.has_suspicious_tld,
        has_homoglyphs=parsed.has_homoglyphs,
        has_embedded_credentials=parsed.has_embedded_credentials,
        has_executable_extension=parsed.has_executable_extension,
        risk_score=score,
        findings=findings
    )
