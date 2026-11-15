import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.responses import Verdict

client = TestClient(app)

MANDATORY_DISCLAIMER_SNIPPET = "This assessment is based on the submitted content and available checks."


# ============================================================================
# 1. MESSAGE ANALYSIS MATRIX
# ============================================================================

def test_matrix_urgent_phishing_sms():
    """Urgent demand coupled with OTP solicitation must yield SUSPICIOUS verdict."""
    payload = {
        "input_type": "message",
        "content": "URGENT: Your bank account will be suspended within 24 hours. Send your OTP immediately to cancel this action and verify your identity."
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert data["risk_score"] >= 60
    assert any("cred_harvest_request" in f["rule_id"] for f in data["findings"])
    assert any("urgent_demand_language" in f["rule_id"] for f in data["findings"])
    assert any(MANDATORY_DISCLAIMER_SNIPPET in l for l in data["limitations"])


def test_matrix_digital_arrest_scam():
    """Digital-arrest extortion (authority + threat + secrecy + money) must trigger synergy and high score."""
    payload = {
        "input_type": "message",
        "content": (
            "This is Inspector Sharma from Central Bureau of Investigation CBI Cyber Crime Cell. "
            "A non-bailable arrest warrant has been registered against you for an illegal customs parcel containing narcotics. "
            "You are placed under digital arrest. Transfer the verification bail deposit of INR 50000 immediately via bank transfer to the government escrow account. "
            "Keep this strictly confidential under Official Secrecy Act and do not disconnect this video call."
        )
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert data["risk_score"] >= 75
    assert data["category"] == "digital_arrest_and_authority_impersonation"
    assert any("digital_arrest_composite_pattern" in f["rule_id"] for f in data["findings"])


def test_matrix_benign_work_message():
    """Standard professional communication must be classified as APPEARS_SAFE with 0 or near-0 score."""
    payload = {
        "input_type": "message",
        "content": "Good morning team, our sprint retrospective is moved to 3 PM today in Room 4B. Please update your Jira tickets beforehand."
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
    assert data["risk_score"] == 0
    assert len(data["findings"]) == 0


def test_matrix_educational_negation_awareness():
    """Educational awareness message ('Never share your OTP') must not trigger credential alerts."""
    payload = {
        "input_type": "message",
        "content": "Cybersecurity Awareness Bulletin: Never share your OTP, banking password, or debit card PIN with anyone over the phone or email."
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
    assert data["risk_score"] < 25
    assert not any("cred_harvest_request" in f["rule_id"] for f in data["findings"])


def test_matrix_zero_width_character_obfuscation():
    """Messages with zero-width spaces or mixed casing must be normalized and detected."""
    # Insert zero-width spaces: U+200B and U+FEFF
    obfuscated = "U\u200br\u200cg\ufeffe\u200bnt: S\u200cend your O\u200cT\ufeffP right now to cancel"
    payload = {
        "input_type": "message",
        "content": obfuscated
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert any("cred_harvest_request" in f["rule_id"] for f in data["findings"])


# ============================================================================
# 2. URL ANALYSIS MATRIX
# ============================================================================

def test_matrix_url_deceptive_subdomain():
    payload = {
        "input_type": "url",
        "content": "https://paypal.com.account-verification-portal.xyz/secure/login"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert data["risk_score"] >= 50
    assert any("url_misleading_subdomain" in f["rule_id"] for f in data["findings"])


def test_matrix_url_homoglyph_punycode():
    # Cyrillic 'a' (U+0430)
    payload = {
        "input_type": "url",
        "content": "https://p\u0430ypal.com/signin"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert any("url_homoglyph_punycode" in f["rule_id"] for f in data["findings"])


def test_matrix_url_raw_ip_address():
    payload = {
        "input_type": "url",
        "content": "http://192.168.1.105:8080/banking/login.php"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert any("url_raw_ip_host" in f["rule_id"] for f in data["findings"])


def test_matrix_url_embedded_at_credentials():
    payload = {
        "input_type": "url",
        "content": "https://chase.com:security@phishing-target.net/auth"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert any("url_embedded_credentials" in f["rule_id"] for f in data["findings"])


def test_matrix_url_direct_apk_executable():
    payload = {
        "input_type": "url",
        "content": "https://system-update.org/android-patch.apk"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert any("url_direct_executable_download" in f["rule_id"] for f in data["findings"])


def test_matrix_url_shortener_alone_not_false_alarm():
    """An isolated shortened URL alone should be noted, but not trigger a high-risk false positive."""
    payload = {
        "input_type": "url",
        "content": "https://bit.ly/3XampleSuspicious"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
    assert data["risk_score"] < 25
    assert any("url_shortened_destination" in f["rule_id"] for f in data["findings"])


def test_matrix_url_schemeless_raw_domain():
    """Pastes without http:// or https:// must be parsed accurately."""
    payload = {
        "input_type": "url",
        "content": "paypal.com.account-verification-portal.xyz"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert any("url_misleading_subdomain" in f["rule_id"] for f in data["findings"])


def test_matrix_url_batch_multiple_no_averaging():
    """When a benign URL and a critical phishing URL are submitted together, the high risk is preserved."""
    payload = {
        "input_type": "url",
        "content": "https://docs.python.org/3/library/urllib.parse.html https://paypal.com.account-verification-portal.xyz/login"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert data["risk_score"] >= 50
    assert len(data["urls"]) == 2


def test_matrix_url_legitimate_complex_long_url():
    """Legitimate long docs URL must not be flagged solely for length or query parameters."""
    payload = {
        "input_type": "url",
        "content": "https://docs.python.org/3/library/urllib.parse.html?highlight=urlsplit#module-urllib.parse"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
    assert data["risk_score"] == 0
    assert len(data["findings"]) == 0


def test_matrix_url_dangerous_schemes():
    """Executable schemes like javascript: and data: must be caught."""
    schemes = [
        "javascript:alert(document.cookie)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd"
    ]
    for s in schemes:
        resp = client.post("/api/analyze", json={"input_type": "url", "content": s})
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] in [Verdict.SUSPICIOUS.value, Verdict.UNABLE_TO_ASSESS.value]


# ============================================================================
# 3. APP-REQUEST ANALYSIS MATRIX
# ============================================================================

def test_matrix_app_banking_trojan_privileges():
    payload = {
        "input_type": "app_request",
        "content": "Install our system security update from the attached link.",
        "context": {
            "claimed_app_purpose": "Security Update",
            "installation_source": "Telegram Direct APK",
            "requested_permissions": ["BIND_ACCESSIBILITY_SERVICE", "READ_SMS", "SYSTEM_ALERT_WINDOW"]
        }
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert data["risk_score"] >= 50
    assert any("app_accessibility_sms_trojan_pattern" in f["rule_id"] for f in data["findings"])


def test_matrix_app_purpose_mismatch():
    """Calculator requesting SMS and Device Admin must be flagged."""
    payload = {
        "input_type": "app_request",
        "content": "Simple scientific calculator app.",
        "context": {
            "claimed_app_purpose": "Calculator",
            "installation_source": "Web Sideload",
            "requested_permissions": ["READ_SMS", "BIND_DEVICE_ADMIN"]
        }
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert any("app_purpose_permission_mismatch" in f["rule_id"] for f in data["findings"])
    assert any("app_device_admin_privilege" in f["rule_id"] for f in data["findings"])


def test_matrix_app_benign_camera_or_maps():
    """Maps app requesting GPS from Google Play should appear safe."""
    payload = {
        "input_type": "app_request",
        "content": "Navigation and transit directions app.",
        "context": {
            "claimed_app_purpose": "GPS Navigation",
            "installation_source": "Google Play Store",
            "requested_permissions": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"]
        }
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
    assert data["risk_score"] == 0


def test_matrix_app_insufficient_context_graceful():
    """App request without context should not crash and should note lack of declarations."""
    payload = {
        "input_type": "app_request",
        "content": "Download this app to get free rewards.",
        "context": {
            "claimed_app_purpose": None,
            "installation_source": None,
            "requested_permissions": []
        }
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert any("app_context_insufficient" in f["rule_id"] for f in data["findings"])


# ============================================================================
# 4. QUISHING & QR CODE PAYLOAD SIMULATION
# ============================================================================

def test_matrix_quishing_decoded_banking_lure():
    """Simulates payload decoded from a quishing image."""
    decoded_url = "https://chase.com.security-verification-portal.xyz/login"
    payload = {
        "input_type": "url",
        "content": decoded_url
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert any("url_misleading_subdomain" in f["rule_id"] for f in data["findings"])


def test_matrix_quishing_decoded_malware_qr():
    decoded_apk = "https://system-update.org/android-patch.apk"
    payload = {
        "input_type": "url",
        "content": decoded_apk
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert any("url_direct_executable_download" in f["rule_id"] for f in data["findings"])


# ============================================================================
# 5. SECURITY & EDGE CASES
# ============================================================================

def test_matrix_exact_10000_char_boundary():
    """10,000 characters exact is allowed; 10,001 is rejected."""
    boundary_content = "Please verify: " + ("a" * (10000 - len("Please verify: ")))
    assert len(boundary_content) == 10000
    resp_valid = client.post("/api/analyze", json={"input_type": "message", "content": boundary_content})
    assert resp_valid.status_code == 200

    resp_overflow = client.post("/api/analyze", json={"input_type": "message", "content": boundary_content + "x"})
    assert resp_overflow.status_code == 422


def test_matrix_xss_and_html_injection_resilience():
    """Script tags and HTML injections should not cause 500 or execute."""
    injection = "<script>alert('XSS')</script><iframe src='javascript:void(0)'></iframe>' OR 1=1; DROP TABLE users;--"
    resp = client.post("/api/analyze", json={"input_type": "message", "content": injection})
    assert resp.status_code == 200
    data = resp.json()
    assert "verdict" in data
    assert "risk_score" in data
