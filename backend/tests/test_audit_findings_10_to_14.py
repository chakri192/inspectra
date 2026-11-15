import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.responses import Verdict, Severity
from app.engine.ai_analyzer import llama_analyzer
from app.engine.reputation import reputation_service
from app.engine.url_parser import extract_urls_from_text

client = TestClient(app)


def test_finding_10_all_caps_domain_not_dropped():
    """
    Finding 10 (Bug 1): All-caps domains like HDFC-UPDATE.COM must not be dropped by the
    Title-case sentence period filter, while end.Next remains dropped.
    """
    extracted_caps = extract_urls_from_text("Please visit HDFC-UPDATE.COM immediately.")
    assert "HDFC-UPDATE.COM" in extracted_caps

    extracted_period = extract_urls_from_text("mail me at a@example.com and end.Next sentence.")
    assert len(extracted_period) == 0


def test_finding_11_android_permission_prefix_and_human_labels():
    """
    Finding 11 (Bug 2): Manifest permission names with 'android.permission.' prefix
    and human-readable permission labels must trigger detection.
    """
    # 1. android.permission prefix
    resp1 = client.post(
        "/api/analyze",
        json={
            "input_type": "app_request",
            "content": "Install helper update",
            "context": {
                "claimed_app_purpose": "Battery Optimizer",
                "installation_source": "Telegram Channel APK Download",
                "requested_permissions": [
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.READ_SMS"
                ]
            }
        }
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    rule_ids1 = [f["rule_id"] for f in data1["findings"]]
    assert "app_accessibility_sms_trojan_pattern" in rule_ids1
    assert data1["verdict"] == Verdict.SUSPICIOUS.value

    # 2. Human labels
    resp2 = client.post(
        "/api/analyze",
        json={
            "input_type": "app_request",
            "content": "Install helper update",
            "context": {
                "claimed_app_purpose": "Battery Optimizer",
                "installation_source": "Direct APK",
                "requested_permissions": [
                    "Accessibility Service",
                    "Read SMS Messages"
                ]
            }
        }
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    rule_ids2 = [f["rule_id"] for f in data2["findings"]]
    assert "app_accessibility_sms_trojan_pattern" in rule_ids2
    assert data2["verdict"] == Verdict.SUSPICIOUS.value


def test_finding_12_suspicious_wins_over_unable_to_assess():
    """
    Finding 12 (Bug 3): When a malicious URL is detected (e.g. deceptive subdomain, score 60),
    a failed external reputation lookup must NOT downgrade the verdict to unable_to_assess.
    Suspicious must take precedence.
    """
    malicious_url = "https://paypal.com.account-verification-portal.xyz/secure/login"
    reputation_service.set_url_status_map({malicious_url: "failed"})

    try:
        resp = client.post(
            "/api/analyze",
            json={
                "input_type": "url",
                "content": malicious_url,
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["reputation"] == "failed"
        assert data["risk_score"] >= 25
        # Suspicious wins!
        assert data["verdict"] == Verdict.SUSPICIOUS.value
    finally:
        reputation_service.set_url_status_map({})


def test_finding_13_ai_string_false_is_not_suspicious():
    """
    Finding 13 (Bug 4): Model returning is_suspicious as string 'false' must evaluate
    to False and not generate a finding.
    """
    llama_analyzer.set_mock_response({
        "is_suspicious": "false",
        "confidence": 85,
        "primary_threat": "none",
        "detected_tactics": [],
        "explanation": "No threat identified"
    })

    try:
        resp = client.post(
            "/api/analyze",
            json={
                "input_type": "message",
                "content": "Good morning team, let us review the meeting notes.",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        rule_ids = [f["rule_id"] for f in data["findings"]]
        assert "llama_semantic_detection" not in rule_ids
        assert data["verdict"] == Verdict.APPEARS_SAFE.value
    finally:
        llama_analyzer.set_mock_response(None)


def test_finding_14_benign_chat_app_not_flagged():
    """
    Finding 14 (Bug 5): A benign chat app describing 'text messages' and connecting
    to 'WhatsApp' or 'Telegram' must not be flagged as a sideloaded trojan.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "app_request",
            "content": "Modern messaging app for exchanging text messages, photos, and voice notes. Connect with friends across WhatsApp and Telegram easily.",
            "context": {
                "claimed_app_purpose": "Messenger App",
                "installation_source": "Google Play Store",
                "requested_permissions": []
            }
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "app_sideload_untrusted_source" not in rule_ids
    assert "app_accessibility_sms_trojan_pattern" not in rule_ids
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
    assert data["risk_score"] == 0


def test_429_response_carries_cors_headers():
    """
    Verifies that rate limit 429 response contains CORS headers when an Origin is present.
    """
    # Exhaust limit
    for _ in range(60):
        client.post(
            "/api/analyze",
            json={"input_type": "message", "content": "Sample"},
            headers={"Origin": "http://localhost:5173"}
        )

    resp_429 = client.post(
        "/api/analyze",
        json={"input_type": "message", "content": "Sample"},
        headers={"Origin": "http://localhost:5173"}
    )
    assert resp_429.status_code == 429
    assert resp_429.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert resp_429.headers.get("access-control-allow-credentials") == "true"
