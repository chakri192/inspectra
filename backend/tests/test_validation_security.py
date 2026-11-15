import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.responses import Verdict

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_empty_and_whitespace_submission():
    resp = client.post(
        "/api/analyze",
        json={"input_type": "message", "content": "    "},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.UNABLE_TO_ASSESS.value
    assert data["risk_score"] == 0
    assert data["checks"]["text_analysis"] == "skipped"


def test_minimal_insufficient_content():
    resp = client.post(
        "/api/analyze",
        json={"input_type": "message", "content": "hi"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.UNABLE_TO_ASSESS.value
    assert data["risk_score"] == 0


def test_excessively_long_submission():
    """Inputs exceeding 10,000 characters should be rejected cleanly."""
    long_content = "A" * 10001
    resp = client.post(
        "/api/analyze",
        json={"input_type": "message", "content": long_content},
    )
    assert resp.status_code == 422
    data = resp.json()
    assert data["error"] == "validation_error"
    assert "10,000" in data["message"]


def test_malformed_input_type():
    resp = client.post(
        "/api/analyze",
        json={"input_type": "invalid_mode", "content": "some text"},
    )
    assert resp.status_code == 422
    data = resp.json()
    assert data["error"] == "validation_error"


def test_html_and_script_injection_input():
    """
    Submissions containing raw HTML or script tags must be handled safely as text
    without breaking the parser or server.
    """
    html_input = "<script>alert('xss');</script><img src=x onerror=alert(1)> Click here to login: https://example.com"
    resp = client.post(
        "/api/analyze",
        json={"input_type": "message", "content": html_input},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "verdict" in data
    assert "risk_score" in data


def test_dangerous_url_scheme():
    """
    Dangerous schemes like javascript: or data: should be identified as invalid/unsupported or flagged.
    """
    resp = client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "javascript:alert(document.cookie)"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in [Verdict.SUSPICIOUS.value, Verdict.UNABLE_TO_ASSESS.value]


def test_unsupported_url_scheme_rejected_422():
    """
    Finding 2: When URL input has a disallowed network scheme such as ftp://,
    it must be rejected cleanly with 422 validation_error.
    """
    resp = client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "ftp://example.com/file.txt"},
    )
    assert resp.status_code == 422
    data = resp.json()
    assert data["error"] == "validation_error"
    assert "Unsupported URL scheme" in data["message"]


def test_static_routes_exempt_from_rate_limit_and_security_headers_present():
    """
    Finding 1: Static and health routes are exempt from the 60 req/min rate limit.
    Making 70 requests to a static/health path does NOT trigger 429.
    Subsequent API requests exceeding the limit return 429 with security headers present.
    """
    # 70 requests to health path
    for _ in range(70):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert "x-content-type-options" in resp.headers
        assert resp.headers["x-content-type-options"] == "nosniff"

    # 60 requests to /api/analyze succeed
    for _ in range(60):
        resp = client.post(
            "/api/analyze",
            json={"input_type": "message", "content": "Valid test content"},
        )
        assert resp.status_code == 200

    # 61st request to /api/analyze hits 429 and carries security headers
    resp_429 = client.post(
        "/api/analyze",
        json={"input_type": "message", "content": "Valid test content"},
    )
    assert resp_429.status_code == 429
    assert resp_429.json()["error"] == "rate_limit_exceeded"
    assert "x-content-type-options" in resp_429.headers
    assert resp_429.headers["x-content-type-options"] == "nosniff"
    assert "x-frame-options" in resp_429.headers


def test_safe_threshold_setting_removed():
    """
    Finding 9: Confirms unused SAFE_THRESHOLD setting has been removed from Settings.
    """
    from app.config import settings
    assert not hasattr(settings, "SAFE_THRESHOLD")
