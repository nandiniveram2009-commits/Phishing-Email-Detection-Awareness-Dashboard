import pytest
from backend.services.sender_analyzer import analyze_sender
from backend.services.url_analyzer import analyze_url
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.risk_engine import calculate_phishing_score

def test_safe_sender():
    res = analyze_sender("support@example.org")
    assert res["sender_risk_score"] == 0

def test_suspicious_sender():
    res = analyze_sender("admin@micros0ft-secure-login.invalid.test")
    assert res["sender_risk_score"] > 0

def test_safe_url():
    res = analyze_url("https://example.org/help")
    assert res["url_risk_score"] == 0

def test_ip_url():
    res = analyze_url("http://198.51.100.10/login")
    assert res["url_risk_score"] >= 40

def test_suspicious_attachment():
    res = analyze_attachment("statement.pdf.exe")
    assert res["attachment_risk_score"] >= 40

def test_phishing_scoring_engine():
    result = calculate_phishing_score(
        sender="admin@account-check.invalid.test",
        subject="URGENT: Verify Account",
        body="Verify your password immediately or account suspended.",
        urls_str="http://198.51.100.15/verify",
        attachment_name="invoice.exe"
    )
    assert result["risk_score"] > 70
    assert result["classification"] == "HIGH RISK / LIKELY PHISHING"
