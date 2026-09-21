"""
Tests for GmailGuard Gemini AI Analysis Service (backend/gemini_service.py)
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from backend.gemini_service import (
    _clean_json_text,
    _extract_fields_via_regex,
    _sanitize_text,
    build_email_analysis_payload,
    is_gemini_available,
    run_gemini_analysis,
)


def test_sanitize_text():
    assert _sanitize_text("") == ""
    assert _sanitize_text("   hello   ") == "hello"
    long_str = "a" * 15000
    sanitized = _sanitize_text(long_str, max_chars=100)
    assert len(sanitized) < 200
    assert "Truncated" in sanitized


def test_clean_json_text():
    raw_markdown = "```json\n{\"classification\": \"phishing\"}\n```"
    assert _clean_json_text(raw_markdown) == '{"classification": "phishing"}'

    raw_plain = "  {\"classification\": \"benign\"}  "
    assert _clean_json_text(raw_plain) == '{"classification": "benign"}'


def test_extract_fields_via_regex():
    malformed = """
    Here is the verdict:
    "classification": "phishing",
    "risk_level": "critical",
    "confidence": 92,
    "summary": "Urgent credential harvesting detected.",
    "explanation": "The email urges password reset."
    """
    fields = _extract_fields_via_regex(malformed)
    assert fields["classification"] == "phishing"
    assert fields["risk_level"] == "critical"
    assert fields["confidence"] == 92
    assert fields["summary"] == "Urgent credential harvesting detected."
    assert "password reset" in fields["explanation"]


def test_build_email_analysis_payload():
    mock_report = {
        "email": {
            "from": "Security <sec@fakebank.com>",
            "sender_email": "sec@fakebank.com",
            "sender_name": "Security",
            "sender_domain": "fakebank.com",
            "subject": "Action Required: Account Suspended",
        },
        "authentication": {
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
        },
        "urls": {
            "findings": [
                {
                    "url": "https://fakebank-login.xyz/auth",
                    "domain": "fakebank-login.xyz",
                    "is_suspicious": True,
                    "suspicious_reasons": ["Typosquatting"],
                }
            ]
        },
        "threat_score": 88,
        "verdict": "CRITICAL",
        "evidence": [
            {"explanation": "SPF and DKIM both failed for sending domain."}
        ],
    }

    raw_email = (
        "From: sec@fakebank.com\r\n"
        "To: victim@example.com\r\n"
        "Subject: Action Required: Account Suspended\r\n"
        "\r\n"
        "Please click here immediately to restore access."
    )

    payload = build_email_analysis_payload(raw_email=raw_email, report=mock_report)
    assert payload["sender_email"] == "sec@fakebank.com"
    assert payload["subject"] == "Action Required: Account Suspended"
    assert payload["authentication"]["spf"] == "FAIL"
    assert payload["threat_score"] == 88
    assert len(payload["extracted_urls"]) == 1
    assert payload["extracted_urls"][0]["url"] == "https://fakebank-login.xyz/auth"
    assert "Please click here" in payload["email_body_text"]


def test_run_gemini_analysis_without_api_key():
    with patch("backend.gemini_service._get_api_key", return_value=""):
        res = run_gemini_analysis(raw_email="test", report={})
        assert res["available"] is False
        assert "GEMINI_API_KEY is not configured" in res["reason"]
        assert res["confidence"] == 0


def test_run_gemini_analysis_mocked_success():
    mock_ai_response = {
        "classification": "phishing",
        "risk_level": "high",
        "confidence": 95,
        "summary": "Sophisticated banking credential harvesting attempt.",
        "threat_indicators": [
            {
                "indicator": "Domain Impersonation",
                "evidence": "Display name claims Bank of America but sender is @fake-verify.top",
                "severity": "high",
            }
        ],
        "social_engineering_indicators": ["Manufactured urgency", "Account lockout coercion"],
        "suspicious_urls": ["http://fake-verify.top/login"],
        "suspicious_domains": ["fake-verify.top"],
        "recommended_actions": ["Block sender domain", "Reset user credentials if link was visited"],
        "explanation": "This email uses high-pressure psychological coercion to induce the user into entering credentials on an unverified domain.",
    }

    fake_response = MagicMock()
    fake_response.text = f"```json\n{json.dumps(mock_ai_response)}\n```"

    with patch("backend.gemini_service._get_api_key", return_value="AIzaSyFakeKey123"):
        with patch("google.genai.Client") as MockClient:
            mock_client_instance = MockClient.return_value
            mock_client_instance.models.generate_content.return_value = fake_response

            result = run_gemini_analysis(raw_email="From: test@fake.com", report={})

            assert result["available"] is True
            assert result["classification"] == "phishing"
            assert result["risk_level"] == "high"
            assert result["confidence"] == 95
            assert len(result["threat_indicators"]) == 1
            assert "Manufactured urgency" in result["social_engineering_indicators"]
            assert "fake-verify.top" in result["suspicious_domains"]
            assert len(result["recommended_actions"]) == 2
