import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.responses import Verdict

client = TestClient(app)


def test_benign_message():
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "Hi Alex, hope you are having a great week! Let's schedule the project sync meeting for tomorrow at 3 PM in conference room B.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
    assert data["risk_score"] < 25
    assert len(data["findings"]) == 0
    assert data["checks"]["text_analysis"] == "completed"


def test_suspicious_credential_request():
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "URGENT: Your bank account will be suspended within 24 hours. Send your OTP immediately to cancel this action.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert data["risk_score"] >= 45
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "cred_harvest_request" in rule_ids
    assert "urgent_demand_language" in rule_ids


def test_educational_text_mentioning_phishing():
    """
    Context awareness test:
    'Never share your OTP' must NOT be classified as an active credential-harvesting phishing attack.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "Cybersecurity Awareness Tip: Never share your OTP, password, or PIN with anyone. Bank representatives will never call you to ask for your verification code.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "cred_harvest_request" not in rule_ids
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
    assert data["risk_score"] < 25


def test_digital_arrest_authority_impersonation():
    """
    Authority impersonation with payment demands and secrecy coercion.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "This is Inspector Verma from Central Bureau of Investigation CBI Cyber Crime Cell. A non-bailable arrest warrant has been registered under your name regarding an illegal parcel. You are placed under digital arrest. Transfer the verification bail amount immediately via bank transfer to the government escrow account. Do not inform anyone or disconnect this video call, keep this strictly confidential under Official Secrecy Act.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert data["risk_score"] >= 75
    assert data["category"] == "digital_arrest_and_authority_impersonation"
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "authority_impersonation" in rule_ids
    assert "threatening_consequences" in rule_ids
    assert "payment_transfer_demand" in rule_ids
    assert "secrecy_isolation_pressure" in rule_ids
    assert "digital_arrest_composite_pattern" in rule_ids


def test_unofficial_sender_mobile_number_detection():
    """
    Alerts from standard personal mobile phone numbers combined with threats or credential demands
    must trigger the unofficial sender mobile number indicator.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "+91 9876543210: Dear customer, your bank account is blocked. Send your OTP immediately to verify your identity.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "unofficial_sender_mobile_number" in rule_ids
    assert "cred_harvest_request" in rule_ids


def test_customs_courier_contraband_parcel_scam():
    """
    Claims of seized contraband packages from FedEx, DHL, or Customs must trigger courier_customs_contraband_parcel.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "Your FedEx parcel containing 5 fake passports and 150g MDMA has been seized by customs clearance officer at Mumbai airport.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "courier_customs_contraband_parcel" in rule_ids


def test_utility_electricity_disconnection_threat():
    """
    Imminent electricity or power disconnection threats must trigger utility_service_disconnection_threat.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because previous month bill was not updated. Please call officer immediately.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "utility_service_disconnection_threat" in rule_ids
