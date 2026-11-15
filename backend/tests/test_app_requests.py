import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.responses import Verdict

client = TestClient(app)


def test_app_request_banking_trojan_permissions():
    """
    Accessibility Service combined with SMS read/send permissions.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "app_request",
            "content": "Please install this system helper app to optimize device performance.",
            "context": {
                "claimed_app_purpose": "Performance Optimizer",
                "installation_source": "Telegram channel APK download",
                "requested_permissions": [
                    "BIND_ACCESSIBILITY_SERVICE",
                    "READ_SMS",
                    "RECEIVE_SMS",
                    "SYSTEM_ALERT_WINDOW"
                ]
            }
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert data["risk_score"] >= 50
    assert data["category"] == "suspicious_app_installation"
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "app_accessibility_sms_trojan_pattern" in rule_ids
    assert "app_sideload_untrusted_source" in rule_ids
    assert data["checks"]["app_permission_analysis"] == "completed"


def test_app_request_purpose_mismatch():
    """
    Basic utility (Calculator) demanding high-risk permissions.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "app_request",
            "content": "A simple Scientific Calculator app that asks for device admin and SMS access.",
            "context": {
                "claimed_app_purpose": "Calculator",
                "installation_source": "Direct APK",
                "requested_permissions": ["SMS", "Device Administrator"]
            }
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "app_purpose_permission_mismatch" in rule_ids
    assert "app_device_admin_privilege" in rule_ids


def test_app_request_insufficient_context():
    """
    App submission with no permissions or source specified.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "app_request",
            "content": "My colleague told me about an app called NotesApp.",
            "context": {
                "claimed_app_purpose": None,
                "installation_source": None,
                "requested_permissions": []
            }
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "app_context_insufficient" in rule_ids
    assert any("evaluates supplied text and permissions only" in lim for lim in data["limitations"])


def test_benign_app_text_word_boundary_no_false_positives():
    """
    Finding 4: Benign app text mentioning 'contact support', 'accessibility' (as a feature),
    and 'alarming' must not trigger contacts/calls permission, accessibility trojan,
    or purpose mismatch findings.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "app_request",
            "content": "If you have questions, please contact support. Our app features high accessibility settings and avoids alarming battery drains.",
            "context": {
                "claimed_app_purpose": "Document Viewer",
                "installation_source": "Google Play",
                "requested_permissions": []
            }
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    rule_ids = [f["rule_id"] for f in data["findings"]]
    # Must NOT have triggered purpose mismatch or dangerous trojan permissions
    assert "app_purpose_permission_mismatch" not in rule_ids
    assert "app_accessibility_sms_trojan_pattern" not in rule_ids
    assert "app_sideload_untrusted_source" not in rule_ids
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
