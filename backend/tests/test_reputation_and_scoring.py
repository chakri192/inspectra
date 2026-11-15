import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.responses import Verdict
from app.engine.reputation import reputation_service

client = TestClient(app)


def test_external_provider_failure_reporting():
    """
    If an external service is unavailable, show the failed check explicitly.
    Never convert a failed check into a clean result.
    """
    reputation_service.set_test_simulate_failure(True)
    try:
        resp = client.post(
            "/api/analyze",
            json={
                "input_type": "url",
                "content": "https://example.com/check-link",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # Explicitly reports failed, never converted to 'completed' or 'safe'
        assert data["checks"]["reputation"] == "failed"
        # Verdict reflects that essential external check failed
        assert data["verdict"] == Verdict.UNABLE_TO_ASSESS.value
    finally:
        reputation_service.set_test_simulate_failure(False)


def test_scoring_diminishing_returns_and_consistency():
    """
    Verifies that repetitive urgency words do not inflate scores infinitely,
    while distinct scam vectors properly escalate score.
    """
    # Repetitive urgency in single message
    resp1 = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "Urgent! Immediate action required right now within 24 hours at once without delay!",
        },
    )
    assert resp1.status_code == 200
    score1 = resp1.json()["risk_score"]

    # Authority + Urgency + Payment + Secrecy (multi-vector)
    resp2 = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "CBI Police Notice: Immediate action required. Arrest warrant issued. Transfer Rs 50,000 to safe account. Keep this strictly confidential.",
        },
    )
    assert resp2.status_code == 200
    score2 = resp2.json()["risk_score"]

    # Multi-vector scam score must be significantly higher than repetitive single-signal text
    assert score2 > score1
    assert score2 >= 70
    assert score2 <= 100


def test_verdict_threshold_consistency():
    """
    Verifies that verdict strictly follows scoring and severity rules:
    - Clean text -> appears_safe
    - Critical finding -> suspicious
    """
    # Clean text
    resp_clean = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "Good morning team, our sprint retrospective is scheduled for Friday at 10 AM.",
        },
    )
    assert resp_clean.status_code == 200
    assert resp_clean.json()["verdict"] == Verdict.APPEARS_SAFE.value
    assert resp_clean.json()["risk_score"] == 0

    # High risk text
    resp_high = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "Send your bank login password and OTP right now to prevent account closure.",
        },
    )
    assert resp_high.status_code == 200
    assert resp_high.json()["verdict"] == Verdict.SUSPICIOUS.value
    assert resp_high.json()["risk_score"] >= 45


def test_multi_url_reputation_failed_is_sticky():
    """
    Finding 7(a): When multiple URLs are evaluated and URL 1 fails while URL 2 completes,
    checks['reputation'] must be 'failed' and verdict must be 'unable_to_assess'.
    """
    url1 = "https://url-fail-lookup.com"
    url2 = "https://url-pass-lookup.com"
    reputation_service.set_url_status_map({
        url1: "failed",
        url2: "completed",
    })
    try:
        resp = client.post(
            "/api/analyze",
            json={
                "input_type": "url",
                "content": f"{url1} {url2}",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["reputation"] == "failed"
        assert data["verdict"] == Verdict.UNABLE_TO_ASSESS.value
    finally:
        reputation_service.set_url_status_map({})


def test_insufficient_input_includes_ai_check_and_limitations():
    """
    Finding 7(c): Insufficient input returns ai_semantic_analysis in checks
    and includes coordinator limitations list.
    """
    resp = client.post(
        "/api/analyze",
        json={"input_type": "message", "content": "hi"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "ai_semantic_analysis" in data["checks"]
    assert data["checks"]["ai_semantic_analysis"] == "skipped"
    assert "limitations" in data
    assert len(data["limitations"]) >= 3
    assert "This assessment is based on the submitted content" in data["limitations"][0]
