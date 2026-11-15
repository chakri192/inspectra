import re
from typing import List, Dict, Tuple, Optional
from app.engine.rules.base import Rule, ThreatCategory
from app.models.responses import Severity, Finding
from app.engine.context_classifier import is_negated_or_educational, is_overall_educational_content
from app.engine.normalizer import find_evidence_snippet, extract_sentences

# --- Message Rule Definitions ---

RULE_CREDENTIAL_HARVEST = Rule(
    rule_id="cred_harvest_request",
    name="Sensitive Credential or OTP Request",
    category=ThreatCategory.PHISHING,
    severity=Severity.CRITICAL,
    score_contribution=45,
    user_explanation="The message solicits sensitive credentials such as a one-time password (OTP), PIN, or login credentials.",
    signal_family="credentials"
)

RULE_URGENT_DEMAND = Rule(
    rule_id="urgent_demand_language",
    name="Artificial Urgency or Time Pressure",
    category=ThreatCategory.PHISHING,
    severity=Severity.MEDIUM,
    score_contribution=20,
    user_explanation="The message uses artificial time pressure (e.g., 'within 24 hours', 'immediate action required') to force hasty compliance.",
    signal_family="urgency"
)

RULE_THREAT_CONSEQUENCE = Rule(
    rule_id="threatening_consequences",
    name="Threat of Immediate Adverse Action",
    category=ThreatCategory.DIGITAL_ARREST,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The message threatens severe adverse consequences such as arrest, account suspension, legal action, or service disconnection.",
    signal_family="threat"
)

RULE_AUTHORITY_IMPERSONATION = Rule(
    rule_id="authority_impersonation",
    name="Claim of Official or Institutional Authority",
    category=ThreatCategory.DIGITAL_ARREST,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The message claims authority from a law enforcement, judicial, or governmental agency (e.g., Police, Court, Customs, CBI, IRS).",
    signal_family="authority"
)

RULE_PAYMENT_DEMAND = Rule(
    rule_id="payment_transfer_demand",
    name="Demand for Direct Money or Account Transfer",
    category=ThreatCategory.DIGITAL_ARREST,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The message demands an urgent payment, security deposit, bail clearance, or bank transfer.",
    signal_family="payment"
)

RULE_SECRECY_PRESSURE = Rule(
    rule_id="secrecy_isolation_pressure",
    name="Pressure for Secrecy and Isolation",
    category=ThreatCategory.DIGITAL_ARREST,
    severity=Severity.HIGH,
    score_contribution=30,
    user_explanation="The message instructs the recipient to maintain strict confidentiality, stay in isolation, or not consult others.",
    signal_family="secrecy"
)

RULE_REMOTE_ACCESS_REQUEST = Rule(
    rule_id="remote_access_software_request",
    name="Request to Install Remote-Control Software",
    category=ThreatCategory.APP_INSTALLATION,
    severity=Severity.HIGH,
    score_contribution=40,
    user_explanation="The message requests the installation of remote desktop software (e.g., AnyDesk, TeamViewer, QuickSupport) under the guise of verification or support.",
    signal_family="remote_access"
)

RULE_SECURITY_DISABLE = Rule(
    rule_id="security_disable_instruction",
    name="Instruction to Disable Device Protections",
    category=ThreatCategory.APP_INSTALLATION,
    severity=Severity.CRITICAL,
    score_contribution=45,
    user_explanation="The message instructs the recipient to turn off Play Protect, disable antivirus, or bypass security warnings.",
    signal_family="security_tamper"
)

RULE_UNOFFICIAL_SENDER_NUMBER = Rule(
    rule_id="unofficial_sender_mobile_number",
    name="Alert Originated from Personal Mobile Number",
    category=ThreatCategory.PHISHING,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The banking, security, or authority notification was sent from a personal mobile phone number rather than an official registered shortcode or alphanumeric sender ID.",
    signal_family="sender_identity"
)

RULE_COURIER_CUSTOMS_SCAM = Rule(
    rule_id="courier_customs_contraband_parcel",
    name="Customs or Courier Contraband Parcel Seizure Claim",
    category=ThreatCategory.DIGITAL_ARREST,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The message claims that an illegal, detained, or contraband parcel (e.g., FedEx, DHL, Customs) containing narcotics or illicit documents was intercepted in your name.",
    signal_family="customs_parcel"
)

RULE_UTILITY_DISCONNECTION_THREAT = Rule(
    rule_id="utility_service_disconnection_threat",
    name="Imminent Utility or Telecom Disconnection Threat",
    category=ThreatCategory.PHISHING,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The message threatens imminent disconnection of essential electricity, power, water, or telecommunication services to force urgent compliance.",
    signal_family="utility_threat"
)

# Synergy / Composite Rules
RULE_DIGITAL_ARREST_SYNERGY = Rule(
    rule_id="digital_arrest_composite_pattern",
    name="Classic Digital-Arrest Scam Pattern",
    category=ThreatCategory.DIGITAL_ARREST,
    severity=Severity.CRITICAL,
    score_contribution=30,  # Synergy bonus
    user_explanation="The message combines official authority claims, arrest threats, secrecy demands, and payment requests, characteristic of digital-arrest scams.",
    signal_family="synergy_digital_arrest"
)

RULE_CREDENTIAL_PHISHING_SYNERGY = Rule(
    rule_id="credential_phishing_composite",
    name="Coercive Credential Phishing Pattern",
    category=ThreatCategory.PHISHING,
    severity=Severity.HIGH,
    score_contribution=25,  # Synergy bonus
    user_explanation="The message couples urgent account threats with direct requests for credentials or verification links.",
    signal_family="synergy_phishing"
)

MESSAGE_RULES = [
    RULE_CREDENTIAL_HARVEST,
    RULE_URGENT_DEMAND,
    RULE_THREAT_CONSEQUENCE,
    RULE_AUTHORITY_IMPERSONATION,
    RULE_PAYMENT_DEMAND,
    RULE_SECRECY_PRESSURE,
    RULE_REMOTE_ACCESS_REQUEST,
    RULE_SECURITY_DISABLE,
    RULE_UNOFFICIAL_SENDER_NUMBER,
    RULE_COURIER_CUSTOMS_SCAM,
    RULE_UTILITY_DISCONNECTION_THREAT,
    RULE_DIGITAL_ARREST_SYNERGY,
    RULE_CREDENTIAL_PHISHING_SYNERGY,
]


# Regex patterns for message analysis
CREDENTIAL_PATTERNS = [
    r"\b(?:send|share|provide|enter|submit|confirm|verify|give|input|disclose|forward|text)\b(?:\W+\w+){0,7}?\W+\b(?:otp|one[- ]time\s+password|passcode|verification\s+code|login\s+pin|mpin|cvv|atm\s+pin|password|passwords|credentials)\b",
    r"\b(?:otp|one[- ]time\s+password|verification\s+code|login\s+pin)\s+(?:is\s+required|needed|needed\s+to\s+cancel|needed\s+immediately|mandatory)\b",
    r"\b(?:give|text|forward)\s+(?:me\s+)?the\s+(?:code|otp|digits|pin|password)\b",
    r"\benter\s+your\s+(?:password|online\s+banking\s+password|credentials|security\s+code)\b",
]

URGENCY_PATTERNS = [
    r"\b(?:within\s+(?:\d+|24|12|48)\s+hours?|immediately|right\s+now|urgent(?:ly)?|at\s+once|without\s+delay|action\s+required\s+now)\b",
    r"\b(?:account\s+will\s+be\s+(?:blocked|suspended|terminated|deleted|frozen)\s+(?:within|today|immediately))\b",
    r"\b(?:final\s+notice|last\s+reminder|immediate\s+action\s+required)\b",
]

THREAT_PATTERNS = [
    r"\b(?:arrest\s+warrant|police\s+case|fir\s+registered|court\s+order|legal\s+notice|immediate\s+arrest|non[- ]bailable)\b",
    r"\b(?:sim\s+card\s+will\s+be\s+(?:deactivated|blocked|disconnected)|power\s+will\s+be\s+cut|electricity\s+disconnected)\b",
    r"\b(?:subscription|account|service)\s+will\s+be\s+(?:cancelled|terminated|suspended|deactivated|closed)\b",
    r"\b(?:facing\s+(?:imprisonment|prosecution|fine|jail|penalties))\b",
    r"\b(?:money\s+laundering|illegal\s+parcel|narcotics\s+found|drugs\s+seized|customs\s+violation)\b",
]

AUTHORITY_PATTERNS = [
    r"\b(?:central\s+bureau\s+of\s+investigation|cbi|cyber\s+crime\s+(?:cell|police|department)|customs\s+department|enforcement\s+directorate|telecom\s+regulatory|trai|rbi|interpol|fbi|irs|police\s+headquarters|supreme\s+court)\b",
    r"\b(?:officer\s+[a-z]+|inspector\s+[a-z]+|dsp|dcp|superintendent\s+of\s+police)\b",
    r"\b(?:official\s+investigation|digital\s+arrest|statutory\s+notice)\b",
]

PAYMENT_PATTERNS = [
    r"\b(?:transfer|deposit|pay|send)\s+(?:the\s+)?(?:amount|money|penalty|fine|bail|clearing\s+fee|verification\s+fee|security\s+deposit|funds)\b",
    r"\b(?:upi\s+(?:id|transfer)|bank\s+transfer|gift\s+cards?|cryptocurrency|bitcoin|escrow\s+account)\b",
    r"\b(?:transfer\s+funds\s+to\s+(?:rbi|government|safe)\s+account)\b",
    r"\b(?:pay\s+(?:rs\.?|inr|\$|usd|eur|gbp)\s*\d+)\b",
]

SECRECY_PATTERNS = [
    r"\b(?:keep\s+this\s+(?:confidential|secret|strictly\s+confidential)|do\s+not\s+(?:inform|tell|consult)\s+(?:anyone|family|lawyer|friends))\b",
    r"\b(?:remain\s+in\s+(?:a\s+closed\s+room|isolation)|do\s+not\s+disconnect\s+(?:the\s+call|video)|camera\s+must\s+remain\s+on)\b",
    r"\b(?:official\s+secrecy\s+act|confidential\s+police\s+matter|surveillance\s+mode)\b",
]

REMOTE_ACCESS_PATTERNS = [
    r"\b(?:install|download)\s+(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer|zoho\s+assist|airdroid)\b",
    r"\b(?:share\s+your\s+screen|allow\s+remote\s+access|remote\s+control\s+permission)\b",
]

SECURITY_DISABLE_PATTERNS = [
    r"\b(?:disable|turn\s+off)\s+(?:play\s+protect|google\s+play\s+protect|antivirus|firewall|security\s+protection)\b",
    r"\b(?:allow\s+installation\s+from\s+unknown\s+sources|enable\s+sideloading|bypass\s+security\s+warning)\b",
]

SENDER_PREFIX_PATTERN = re.compile(
    r"(?i)^(?:(?:from|sender|source|orig|src|caller):\s*)?(?:\+?\d{1,3}[-.\s]?)?\(?\d{3,4}\)?[-.\s]?\d{3}[-.\s]?\d{3,5}\s*(?:[:\-])\s*"
)

CUSTOMS_PARCEL_PATTERNS = [
    r"\b(?:fedex|dhl|blue\s*dart|customs\s+(?:clearance|department|officer)|airport\s+customs|mumbai\s+customs|delhi\s+customs)\b.*?\b(?:parcel|shipment|consignment|package|courier)\b",
    r"\b(?:parcel|shipment|consignment|package|courier)\b.*?\b(?:intercepted|seized|detained|held|confiscated)\b.*?\b(?:customs|police|narcotics|drugs|contraband|mdma|passports?|illegal|illicit)\b",
    r"\b(?:illegal\s+parcel|contraband\s+(?:found|parcel)|narcotics\s+found|drugs\s+seized|drugs\s+found\s+in\s+parcel)\b",
    r"\b(?:parcel|shipment|courier)\s+(?:booked|sent|registered)\s+(?:in\s+your\s+name|with\s+your\s+aadhaar|with\s+your\s+id)\b",
]

UTILITY_DISCONNECTION_PATTERNS = [
    r"\b(?:electricity|power|bijli)\s+(?:will\s+be\s+(?:disconnected|cut|stopped)|power\s+cut)\b.*?\b(?:tonight|today|immediately|\d{1,2}[:.]\d{2}\s*(?:pm|am)?)\b",
    r"\b(?:dear\s+consumer|dear\s+customer)\b.*?\b(?:electricity\s+bill|power\s+bill|water\s+bill)\b.*?\b(?:not\s+updated|unpaid|pending)\b",
    r"\b(?:sim\s+card|mobile\s+number)\s+(?:will\s+be\s+(?:deactivated|blocked|disconnected|suspended))\s+(?:within|today|immediately)\b",
    r"\b(?:trai|dot|telecom\s+regulatory)\s+(?:has\s+ordered|order|notice)\s+(?:to\s+block|to\s+deactivate|disconnection)\b",
]


def analyze_message_content(text: str) -> Tuple[List[Finding], Dict[str, bool]]:
    """
    Analyzes message text against phishing, authority impersonation, and coercive patterns.
    Takes context (negation / educational advice) into account.
    Returns (findings, signal_flags).
    """
    findings: List[Finding] = []
    signals: Dict[str, bool] = {
        "credentials": False,
        "urgency": False,
        "threat": False,
        "authority": False,
        "payment": False,
        "secrecy": False,
        "remote_access": False,
        "security_disable": False,
        "customs_parcel": False,
        "utility_threat": False,
        "sender_mobile": False,
    }

    # If the whole content is an educational/advisory bulletin, treat with extra caution
    is_educational = is_overall_educational_content(text)

    sentences = extract_sentences(text)

    # 1. Credential Harvesting (Sensitive to context: 'Never share OTP' must NOT trigger)
    for sentence in sentences:
        if is_negated_or_educational(sentence):
            # Educational/negated: skip flagging as credential harvesting
            continue

        for pat in CREDENTIAL_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["credentials"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_CREDENTIAL_HARVEST.create_finding(evidence))
                signals["credentials"] = True
                break

    # 2. Urgent Demands
    for sentence in sentences:
        if is_educational:
            continue
        for pat in URGENCY_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["urgency"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_URGENT_DEMAND.create_finding(evidence))
                signals["urgency"] = True
                break

    # 3. Threats of Adverse Consequence
    for sentence in sentences:
        if is_educational:
            continue
        for pat in THREAT_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["threat"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_THREAT_CONSEQUENCE.create_finding(evidence))
                signals["threat"] = True
                break

    # 4. Authority Impersonation
    for sentence in sentences:
        if is_educational:
            continue
        for pat in AUTHORITY_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["authority"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_AUTHORITY_IMPERSONATION.create_finding(evidence))
                signals["authority"] = True
                break

    # 5. Payment Demands
    for sentence in sentences:
        if is_educational:
            continue
        for pat in PAYMENT_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["payment"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_PAYMENT_DEMAND.create_finding(evidence))
                signals["payment"] = True
                break

    # 6. Secrecy and Isolation Pressure
    for sentence in sentences:
        if is_educational:
            continue
        for pat in SECRECY_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["secrecy"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_SECRECY_PRESSURE.create_finding(evidence))
                signals["secrecy"] = True
                break

    # 7. Remote Access Software Requests
    for sentence in sentences:
        if is_negated_or_educational(sentence):
            continue
        for pat in REMOTE_ACCESS_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["remote_access"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_REMOTE_ACCESS_REQUEST.create_finding(evidence))
                signals["remote_access"] = True
                break

    # 8. Instructions to Disable Security
    for sentence in sentences:
        if is_negated_or_educational(sentence):
            continue
        for pat in SECURITY_DISABLE_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["security_disable"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_SECURITY_DISABLE.create_finding(evidence))
                signals["security_disable"] = True
                break

    # 9. Customs or Courier Contraband Parcel Claims
    for sentence in sentences:
        if is_educational:
            continue
        for pat in CUSTOMS_PARCEL_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["customs_parcel"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_COURIER_CUSTOMS_SCAM.create_finding(evidence))
                signals["customs_parcel"] = True
                signals["authority"] = True
                signals["threat"] = True
                break

    # 10. Imminent Utility or Telecom Disconnection Threats
    for sentence in sentences:
        if is_educational:
            continue
        for pat in UTILITY_DISCONNECTION_PATTERNS:
            match = re.search(pat, sentence, re.IGNORECASE)
            if match and not signals["utility_threat"]:
                evidence = find_evidence_snippet(text, match.group(0))
                findings.append(RULE_UTILITY_DISCONNECTION_THREAT.create_finding(evidence))
                signals["utility_threat"] = True
                signals["threat"] = True
                break

    # 11. Alert Originated from Personal Mobile Phone Number
    sender_match = SENDER_PREFIX_PATTERN.match(text.strip())
    if sender_match and not is_educational:
        # Check if the alert/threat body contains any concerning institutional or coercion signals
        has_concerning_context = any([
            signals["credentials"],
            signals["urgency"],
            signals["threat"],
            signals["authority"],
            signals["payment"],
            signals["customs_parcel"],
            signals["utility_threat"]
        ])
        if has_concerning_context and not signals["sender_mobile"]:
            evidence = sender_match.group(0).strip()
            findings.append(RULE_UNOFFICIAL_SENDER_NUMBER.create_finding(evidence))
            signals["sender_mobile"] = True

    # --- Synergy Combinations ---
    # Digital arrest synergy: Authority + Threat + (Payment or Secrecy)
    digital_arrest_signals = [signals["authority"], signals["threat"], (signals["payment"] or signals["secrecy"])]
    if all(digital_arrest_signals):
        findings.append(RULE_DIGITAL_ARREST_SYNERGY.create_finding(
            "Combined indicators: Institutional authority claim + adverse threat + financial/secrecy coercion"
        ))

    # Credential phishing synergy: Urgency/Threat + Credential harvest
    if signals["credentials"] and (signals["urgency"] or signals["threat"]):
        findings.append(RULE_CREDENTIAL_PHISHING_SYNERGY.create_finding(
            "Combined indicators: Urgent or threatening demand coupled with direct credential/OTP request"
        ))

    return findings, signals
