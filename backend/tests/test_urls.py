import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.responses import Verdict

client = TestClient(app)


def test_legitimate_url_with_long_path():
    """
    Legitimate URL with deep path and query arguments must NOT be flagged solely because it is long.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "url",
            "content": "https://docs.python.org/3/library/urllib.parse.html?highlight=urlsplit#module-urllib.parse-long-anchor-section-details-reference",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.APPEARS_SAFE.value
    assert data["risk_score"] < 25
    assert len(data["findings"]) == 0
    assert data["urls"][0]["domain"] == "python.org"


def test_misleading_subdomain():
    """
    Deceptive subdomain impersonating a brand on an unrelated root domain.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "url",
            "content": "https://paypal.com.account-verification-portal.xyz/secure/login",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert data["risk_score"] >= 40
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "url_misleading_subdomain" in rule_ids
    assert data["urls"][0]["domain"] == "account-verification-portal.xyz"


def test_raw_ip_address_host():
    """
    Direct IP address URL.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "url",
            "content": "http://192.168.1.55/banking/login.php",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "url_raw_ip_host" in rule_ids
    assert data["urls"][0]["is_ip"] is True


def test_homoglyph_lookalike_domain():
    """
    Punycode / Cyrillic confusable homoglyphs.
    """
    # Host contains Cyrillic 'а' (\u0430) instead of Latin 'a'
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "url",
            "content": "https://p\u0430ypal.com/signin",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "url_homoglyph_punycode" in rule_ids


def test_embedded_credentials_at_symbol():
    """
    Misleading @ syntax in authority.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "url",
            "content": "https://chase.com:secure-login@malicious-phishing-host.net/auth",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "url_embedded_credentials" in rule_ids
    assert data["urls"][0]["has_embedded_credentials"] is True


def test_multiple_urls_no_averaging_away():
    """
    When one benign URL and one high-risk URL are submitted together:
    - Findings and scores must NOT average away the high-risk finding.
    - Combined score must reflect the high-risk indicator.
    - Both URLs must appear in the breakdown.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "url",
            "content": "Check this resource https://wikipedia.org/wiki/Computer_security and then download update from https://microsoft.com.account-update.xyz/patch.apk",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == Verdict.SUSPICIOUS.value
    assert len(data["urls"]) == 2
    apk_url = next(u for u in data["urls"] if "account-update.xyz" in u["domain"])
    wiki_url = next(u for u in data["urls"] if "wikipedia.org" in u["domain"])
    assert apk_url["risk_score"] >= 40
    assert wiki_url["risk_score"] == 0
    assert data["risk_score"] >= apk_url["risk_score"]


def test_bare_ip_and_short_host_url_sufficiency():
    """
    Finding 3: Bare IPs (e.g. 192.168.1.105) and short hostnames (e.g. https://t.co/x)
    must not be treated as insufficient input; verdict must not be unable_to_assess,
    and the raw IP host finding must be triggered for bare IPs.
    """
    # 1. Bare IP address
    resp_ip = client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "192.168.1.105"},
    )
    assert resp_ip.status_code == 200
    data_ip = resp_ip.json()
    assert data_ip["verdict"] != Verdict.UNABLE_TO_ASSESS.value
    assert data_ip["verdict"] == Verdict.SUSPICIOUS.value
    rule_ids = [f["rule_id"] for f in data_ip["findings"]]
    assert "url_raw_ip_host" in rule_ids

    # 2. Short URL host
    resp_short = client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://t.co/x"},
    )
    assert resp_short.status_code == 200
    data_short = resp_short.json()
    assert data_short["verdict"] != Verdict.UNABLE_TO_ASSESS.value


def test_schemeless_url_postfilter_email_and_sentence_period():
    """
    Finding 5: Text containing email addresses (e.g. a@example.com) and sentence-ending
    tokens without spaces (e.g. end.Next) must NOT be extracted as URLs.
    """
    resp = client.post(
        "/api/analyze",
        json={
            "input_type": "message",
            "content": "Please mail me at a@example.com and end.Next sentence will follow.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["urls"]) == 0
