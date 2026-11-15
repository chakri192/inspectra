import pytest
from starlette.testclient import TestClient
from app.main import app
from app.engine.ai_analyzer import llama_analyzer
from app.models.responses import Verdict

client = TestClient(app)


def test_llama_disabled_reports_not_configured():
    """When LLaMA is not enabled, check status reports 'not_configured'."""
    orig_enabled = llama_analyzer.enabled
    llama_analyzer.enabled = False
    llama_analyzer.set_mock_response(None)
    llama_analyzer.set_simulate_failure(False)

    try:
        resp = client.post(
            "/api/analyze",
            json={"input_type": "message", "content": "Hello team, let's meet tomorrow."},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["ai_semantic_analysis"] == "not_configured"
    finally:
        llama_analyzer.enabled = orig_enabled


def test_llama_ai_detection_and_finding():
    """When LLaMA is enabled and returns suspicious evaluation, finding is generated."""
    mock_llm_output = {
        "is_suspicious": True,
        "confidence": 85,
        "primary_threat": "phishing",
        "detected_tactics": ["Urgent coercion", "Account lockout pretext"],
        "evidence_excerpt": "Your account has been locked",
        "explanation": "Semantic analysis detected psychological urgency to force credential disclosure."
    }
    llama_analyzer.set_mock_response(mock_llm_output)

    try:
        resp = client.post(
            "/api/analyze",
            json={
                "input_type": "message",
                "content": "Alert: Your account has been locked. Verify immediately.",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["ai_semantic_analysis"] == "completed"
        rule_ids = [f["rule_id"] for f in data["findings"]]
        assert "llama_semantic_detection" in rule_ids
        assert data["verdict"] == Verdict.SUSPICIOUS.value
    finally:
        llama_analyzer.set_mock_response(None)


def test_llama_ai_failure_resilience():
    """When LLaMA call encounters an error or timeout, reports 'failed' without breaking the engine."""
    llama_analyzer.set_simulate_failure(True)

    try:
        resp = client.post(
            "/api/analyze",
            json={
                "input_type": "message",
                "content": "Good afternoon, sharing the quarterly review notes.",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["ai_semantic_analysis"] == "failed"
    finally:
        llama_analyzer.set_simulate_failure(False)


def test_llama_ai_malformed_outputs_record_failed_gracefully():
    """
    Finding 8: Malformed model outputs (string confidence, non-list tactics, JSON array)
    must record 'failed' and return 200 with normal heuristic assessment, not 500.
    """
    malformed_cases = [
        {"is_suspicious": True, "confidence": "high", "primary_threat": "phishing"},
        {"is_suspicious": True, "confidence": 80, "detected_tactics": "urgent_action_required"},
        [{"is_suspicious": True, "confidence": 80}],
    ]

    for bad_output in malformed_cases:
        llama_analyzer.set_mock_response(bad_output)
        try:
            resp = client.post(
                "/api/analyze",
                json={
                    "input_type": "message",
                    "content": "Good afternoon, sharing the quarterly review notes.",
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["checks"]["ai_semantic_analysis"] == "failed"
            assert data["verdict"] == Verdict.APPEARS_SAFE.value
        finally:
            llama_analyzer.set_mock_response(None)


def test_llama_ai_medium_severity_scores_15_not_25():
    """
    Finding 7(b): When LLaMA returns confidence 50-74 (Severity.MEDIUM),
    the score contribution must be 15, not the fixed 25 from the registry.
    """
    mock_medium_output = {
        "is_suspicious": True,
        "confidence": 60,
        "primary_threat": "phishing",
        "detected_tactics": ["Subtle social engineering"],
        "evidence_excerpt": "Quarterly review notes",
        "explanation": "Potential unverified context.",
    }
    llama_analyzer.set_mock_response(mock_medium_output)

    try:
        resp = client.post(
            "/api/analyze",
            json={
                "input_type": "message",
                "content": "Good afternoon, sharing the quarterly review notes.",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["ai_semantic_analysis"] == "completed"
        ai_finding = next((f for f in data["findings"] if f["rule_id"] == "llama_semantic_detection"), None)
        assert ai_finding is not None
        assert ai_finding["severity"] == "medium"
        assert data["risk_score"] == 15
    finally:
        llama_analyzer.set_mock_response(None)
