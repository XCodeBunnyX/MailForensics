"""End-to-end integration test using sample emails."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import pytest
from pathlib import Path
from main import analyze_email

SAMPLE_DIR = Path(__file__).parent.parent / "sample_emails"


def _load_sample(name: str) -> str:
    path = SAMPLE_DIR / name
    return path.read_text(encoding="utf-8", errors="replace")


class TestEndToEnd:
    def test_phishing_email_returns_dict(self):
        raw = _load_sample("phishing_bank.eml")
        result = analyze_email(raw)
        assert isinstance(result, dict)

    def test_phishing_email_has_required_keys(self):
        raw = _load_sample("phishing_bank.eml")
        result = analyze_email(raw)
        required = [
            "threat_score", "verdict", "email", "authentication",
            "infrastructure", "urls", "attachments", "ml",
            "evidence", "positive_evidence", "limitations",
        ]
        for key in required:
            assert key in result, f"Missing key: {key}"

    def test_phishing_email_score_is_high(self):
        raw = _load_sample("phishing_bank.eml")
        result = analyze_email(raw)
        # Should score significantly above 50
        assert result["threat_score"] >= 50, (
            f"Expected phishing email to score >= 50, got {result['threat_score']}"
        )

    def test_phishing_email_auth_failures(self):
        raw = _load_sample("phishing_bank.eml")
        result = analyze_email(raw)
        auth = result["authentication"]
        # Sample email has spf=fail and dmarc=fail
        assert auth["spf"] == "FAIL"
        assert auth["dmarc"] == "FAIL"

    def test_phishing_email_has_suspicious_urls(self):
        raw = _load_sample("phishing_bank.eml")
        result = analyze_email(raw)
        assert result["urls"]["suspicious"] > 0

    def test_phishing_email_has_suspicious_attachment(self):
        raw = _load_sample("phishing_bank.eml")
        result = analyze_email(raw)
        assert result["attachments"]["count"] >= 1
        assert result["attachments"]["suspicious"] >= 1

    def test_legitimate_email_score_is_low(self):
        raw = _load_sample("legitimate.eml")
        result = analyze_email(raw)
        # Should score below 50
        assert result["threat_score"] <= 50, (
            f"Expected legitimate email to score <= 50, got {result['threat_score']}"
        )

    def test_legitimate_email_auth_pass(self):
        raw = _load_sample("legitimate.eml")
        result = analyze_email(raw)
        auth = result["authentication"]
        assert auth["spf"] == "PASS"
        assert auth["dkim"] == "PASS"
        assert auth["dmarc"] == "PASS"

    def test_ceo_fraud_has_reply_to_warning(self):
        raw = _load_sample("ceo_fraud.eml")
        result = analyze_email(raw)
        # Reply-To differs from From domain — should be in infrastructure or limitations
        infra = result["infrastructure"]
        assert infra["reply_to_differs"] is True

    def test_result_is_json_serializable(self):
        raw = _load_sample("phishing_bank.eml")
        result = analyze_email(raw)
        # Should not raise
        serialized = json.dumps(result, ensure_ascii=False)
        assert len(serialized) > 100

    def test_score_is_int_in_range(self):
        for sample in ["phishing_bank.eml", "legitimate.eml", "ceo_fraud.eml"]:
            raw = _load_sample(sample)
            result = analyze_email(raw)
            assert isinstance(result["threat_score"], int)
            assert 0 <= result["threat_score"] <= 100

    def test_no_exception_on_empty_email(self):
        result = analyze_email("")
        assert isinstance(result, dict)
        assert "threat_score" in result
