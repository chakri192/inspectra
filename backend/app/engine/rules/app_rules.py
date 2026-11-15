import re
from typing import List, Tuple, Optional
from app.engine.rules.base import Rule, ThreatCategory
from app.models.responses import Severity, Finding
from app.models.requests import AppContext
from app.engine.normalizer import find_evidence_snippet


RULE_ACCESSIBILITY_SMS_COMBO = Rule(
    rule_id="app_accessibility_sms_trojan_pattern",
    name="Critical Banking Trojan Permission Combination",
    category=ThreatCategory.APP_INSTALLATION,
    severity=Severity.CRITICAL,
    score_contribution=50,
    user_explanation="The application requests both Accessibility Service and SMS access, a high-severity combination commonly abused by mobile banking trojans to intercept OTPs and automate actions.",
    signal_family="dangerous_permissions"
)

RULE_PURPOSE_PERMISSION_MISMATCH = Rule(
    rule_id="app_purpose_permission_mismatch",
    name="Suspicious Mismatch Between Claimed Purpose and Permissions",
    category=ThreatCategory.APP_INSTALLATION,
    severity=Severity.HIGH,
    score_contribution=40,
    user_explanation="The application claims a basic or non-sensitive utility purpose (e.g., calculator, flashlight, cleaner) but demands high-risk system privileges unrelated to that function.",
    signal_family="purpose_mismatch"
)

RULE_DEVICE_ADMIN_REQUEST = Rule(
    rule_id="app_device_admin_privilege",
    name="High-Privilege Device Administrator Request",
    category=ThreatCategory.APP_INSTALLATION,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The application requests Device Administrator privileges, which allows preventing app removal, wiping device storage, or altering system locks.",
    signal_family="device_admin"
)

RULE_SIDELOAD_SENSITIVE_PERMS = Rule(
    rule_id="app_sideload_untrusted_source",
    name="Untrusted Installation Source with Sensitive Permissions",
    category=ThreatCategory.APP_INSTALLATION,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The application is distributed via direct APK download or messaging channels (sideloading) rather than an official verified store, while requiring sensitive device access.",
    signal_family="installation_source"
)

RULE_NOTIFICATION_OVERLAY_COMBO = Rule(
    rule_id="app_overlay_notification_combo",
    name="Screen Overlay and Notification Interception Privilege",
    category=ThreatCategory.APP_INSTALLATION,
    severity=Severity.HIGH,
    score_contribution=35,
    user_explanation="The combination of 'Draw over other apps' (overlay) and Notification Listener permits fake credential prompts and reading verification notifications.",
    signal_family="overlay_combo"
)

RULE_INSUFFICIENT_APP_CONTEXT = Rule(
    rule_id="app_context_insufficient",
    name="Insufficient Information for Deep App Assessment",
    category=ThreatCategory.APP_INSTALLATION,
    severity=Severity.LOW,
    score_contribution=0,
    user_explanation="No specific permissions or installation details were supplied. Analysis was conducted solely on text and extracted links.",
    signal_family="context_status"
)

APP_RULES = [
    RULE_ACCESSIBILITY_SMS_COMBO,
    RULE_PURPOSE_PERMISSION_MISMATCH,
    RULE_DEVICE_ADMIN_REQUEST,
    RULE_SIDELOAD_SENSITIVE_PERMS,
    RULE_NOTIFICATION_OVERLAY_COMBO,
    RULE_INSUFFICIENT_APP_CONTEXT,
]

# Sensitive permission detection
# Structured manifest permission constants
STRUCTURED_ACCESSIBILITY_PERMS = {
    "BIND_ACCESSIBILITY_SERVICE",
    "ACCESSIBILITY_SERVICE",
    "ACCESSIBILITY",
}
STRUCTURED_SMS_PERMS = {
    "READ_SMS",
    "RECEIVE_SMS",
    "SEND_SMS",
    "RECEIVE_MMS",
    "RECEIVE_WAP_PUSH",
}
STRUCTURED_ADMIN_PERMS = {
    "BIND_DEVICE_ADMIN",
    "DEVICE_ADMIN",
    "DEVICE_ADMINISTRATOR",
}
STRUCTURED_NOTIFICATION_PERMS = {
    "BIND_NOTIFICATION_LISTENER_SERVICE",
    "NOTIFICATION_LISTENER",
    "NOTIFICATION_ACCESS",
}
STRUCTURED_OVERLAY_PERMS = {
    "SYSTEM_ALERT_WINDOW",
    "ACTION_MANAGE_OVERLAY_PERMISSION",
    "OVERLAY",
}
STRUCTURED_INSTALL_PERMS = {
    "REQUEST_INSTALL_PACKAGES",
    "INSTALL_PACKAGES",
}
STRUCTURED_CONTACTS_CALLS_PERMS = {
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "PROCESS_OUTGOING_CALLS",
    "CALL_PHONE",
}

# Free-text permission regexes: require explicit phrases and word boundaries
PERM_ACCESSIBILITY_TEXT = re.compile(
    r"\b(?:accessibility\s+service|bind_accessibility_service)\b",
    re.IGNORECASE
)
PERM_SMS_TEXT = re.compile(
    r"\b(?:read_sms|receive_sms|send_sms|read\s+sms|receive\s+sms|intercept\s+sms|access\s+sms|sms\s+messages?)\b",
    re.IGNORECASE
)
PERM_DEVICE_ADMIN_TEXT = re.compile(
    r"\b(?:device\s+admin(?:istrator)?(?:\s+privilege|\s+permission|\s+access)?|bind_device_admin)\b",
    re.IGNORECASE
)
PERM_NOTIFICATION_TEXT = re.compile(
    r"\b(?:notification\s+listener(?:\s+service)?|notification\s+access|bind_notification_listener_service)\b",
    re.IGNORECASE
)
PERM_OVERLAY_TEXT = re.compile(
    r"\b(?:system_alert_window|draw\s+over(?:\s+other\s+apps)?|display\s+over\s+other\s+apps|screen\s+overlay)\b",
    re.IGNORECASE
)
PERM_UNKNOWN_SOURCES_TEXT = re.compile(
    r"\b(?:unknown\s+sources|install\s+unknown\s+apps|request_install_packages)\b",
    re.IGNORECASE
)
PERM_CONTACTS_CALLS_TEXT = re.compile(
    r"\b(?:read\s+contacts|access\s+contacts|call\s+logs?|make\s+calls?|read_call_log|read_contacts)\b",
    re.IGNORECASE
)

# Low-privilege utility purposes (matched with strict word boundaries)
SIMPLE_UTILITY_PURPOSES = [
    "calculator", "flashlight", "torch", "cleaner", "ram booster",
    "battery saver", "battery optimizer", "wallpaper", "photo filter",
    "pdf reader", "qr scanner", "alarm", "stopwatch", "compass",
    "weather widget", "sound recorder", "notepad"
]

# Patterns for structured installation_source field
STRUCTURED_UNTRUSTED_SOURCES = [
    r"\bdirect\s+apk\b",
    r"\bapk\b",
    r"\bsideload(?:ing)?\b",
    r"\btelegram\b",
    r"\bwhatsapp\b",
    r"\bmediafire\b",
    r"\bmega\b",
    r"\bunknown\b",
    r"\bthird-party\b",
    r"\bbrowser\s+download\b",
]

# Strict patterns for free-text content (requires explicit distribution context, not bare words)
CONTENT_UNTRUSTED_SOURCES = [
    r"\bdirect\s+apk\b",
    r"\bapk\s+download\b",
    r"\bsideload(?:ing)?\b",
    r"\btelegram\s+(?:channel|apk|download|link|group)\b",
    r"\bwhatsapp\s+(?:group|apk|download|link)\b",
    r"\bmediafire(?:\.com)?\b",
    r"\bmega\.nz\b",
    r"\bmega\s+(?:download|link|cloud|folder)\b",
    r"\bunknown\s+(?:sources?|origin|channels?)\b",
    r"\bthird-party\s+(?:apk|store|source)\b",
    r"\bbrowser\s+download\b",
]


def analyze_app_request(content: str, context: Optional[AppContext]) -> Tuple[List[Finding], bool]:
    """
    Evaluates an app-installation request or permission description.
    Scans structured requested_permissions first (normalizing android.permission. prefixes),
    and free text with explicit phrases.
    Returns (findings, has_concerning_indicators).
    """
    findings: List[Finding] = []

    # 1. Scan structured permissions list (strip android.permission. prefix)
    structured_perms = set()
    perm_labels: List[str] = []
    if context and context.requested_permissions:
        for p in context.requested_permissions:
            clean_p = p.strip()
            if clean_p.lower().startswith("android.permission."):
                clean_p = clean_p[len("android.permission."):]
            structured_perms.add(clean_p.upper().strip())
            perm_labels.append(p.strip())

    # Free text search across content and permission label strings
    text_to_scan = content + (" " + " ".join(perm_labels) if perm_labels else "")

    has_acc = bool(structured_perms & STRUCTURED_ACCESSIBILITY_PERMS) or bool(PERM_ACCESSIBILITY_TEXT.search(text_to_scan))
    has_sms = bool(structured_perms & STRUCTURED_SMS_PERMS) or bool(PERM_SMS_TEXT.search(text_to_scan))
    has_admin = bool(structured_perms & STRUCTURED_ADMIN_PERMS) or bool(PERM_DEVICE_ADMIN_TEXT.search(text_to_scan))
    has_notif = bool(structured_perms & STRUCTURED_NOTIFICATION_PERMS) or bool(PERM_NOTIFICATION_TEXT.search(text_to_scan))
    has_overlay = bool(structured_perms & STRUCTURED_OVERLAY_PERMS) or bool(PERM_OVERLAY_TEXT.search(text_to_scan))
    has_unknown = bool(structured_perms & STRUCTURED_INSTALL_PERMS) or bool(PERM_UNKNOWN_SOURCES_TEXT.search(text_to_scan))
    has_contacts = bool(structured_perms & STRUCTURED_CONTACTS_CALLS_PERMS) or bool(PERM_CONTACTS_CALLS_TEXT.search(text_to_scan))

    # 2. Installation source check: check structured context first
    is_untrusted_source = False
    source_text = (context.installation_source or "") if context else ""
    if source_text:
        for pattern in STRUCTURED_UNTRUSTED_SOURCES:
            if re.search(pattern, source_text, re.IGNORECASE):
                is_untrusted_source = True
                break

    # If not found in structured source, check free text with contextual pattern
    if not is_untrusted_source and content:
        for pattern in CONTENT_UNTRUSTED_SOURCES:
            if re.search(pattern, content, re.IGNORECASE):
                is_untrusted_source = True
                break

    # 3. Claimed purpose check: check structured context first
    is_simple_utility = False
    matched_utility = ""
    purpose_text = (context.claimed_app_purpose or "") if context else ""
    if purpose_text:
        for util in SIMPLE_UTILITY_PURPOSES:
            if re.search(r"\b" + re.escape(util) + r"\b", purpose_text, re.IGNORECASE):
                is_simple_utility = True
                matched_utility = util
                break

    # Fallback: scan content for utility purpose with word boundaries
    if not is_simple_utility and content:
        for util in SIMPLE_UTILITY_PURPOSES:
            if re.search(r"\b" + re.escape(util) + r"\b", content, re.IGNORECASE):
                is_simple_utility = True
                matched_utility = util
                break

    # 1. Critical Combination: Accessibility + SMS
    if has_acc and has_sms:
        evidence = "Requested privileges: Accessibility Service and SMS access"
        findings.append(RULE_ACCESSIBILITY_SMS_COMBO.create_finding(evidence))

    # 2. Overlay + Notification Listener
    if has_overlay and has_notif:
        evidence = "Requested privileges: Draw over other apps (overlay) and Notification access"
        findings.append(RULE_NOTIFICATION_OVERLAY_COMBO.create_finding(evidence))

    # 3. Purpose Mismatch (Simple utility demanding sensitive privileges)
    sensitive_privileges = []
    if has_acc:
        sensitive_privileges.append("Accessibility")
    if has_sms:
        sensitive_privileges.append("SMS")
    if has_admin:
        sensitive_privileges.append("Device Admin")
    if has_contacts:
        sensitive_privileges.append("Contacts/Calls")
    if has_unknown:
        sensitive_privileges.append("Install unknown apps")

    if is_simple_utility and sensitive_privileges:
        evidence = f"Claimed purpose '{matched_utility}' requests disproportionate permissions: {', '.join(sensitive_privileges)}"
        findings.append(RULE_PURPOSE_PERMISSION_MISMATCH.create_finding(evidence))

    # 4. Device Administrator privilege
    if has_admin:
        evidence = "Application requests Device Administrator privilege"
        findings.append(RULE_DEVICE_ADMIN_REQUEST.create_finding(evidence))

    # 5. Untrusted Sideloading + Sensitive Permissions
    if is_untrusted_source and (has_acc or has_sms or has_admin or has_contacts or has_unknown):
        evidence = f"Installation from untrusted channel with sensitive requests: {', '.join(sensitive_privileges or ['Sensitive access'])}"
        findings.append(RULE_SIDELOAD_SENSITIVE_PERMS.create_finding(evidence))

    # Check if context was completely empty and no permissions were detectable
    has_any_permission = any([has_acc, has_sms, has_admin, has_notif, has_overlay, has_unknown, has_contacts])
    if not has_any_permission and (not context or not context.requested_permissions):
        # Informational notice about lack of context
        findings.append(RULE_INSUFFICIENT_APP_CONTEXT.create_finding(
            "No specific permissions or manifest declarations supplied in the request."
        ))

    has_concerning = any(f.severity in [Severity.HIGH, Severity.CRITICAL] for f in findings)
    return findings, has_concerning
