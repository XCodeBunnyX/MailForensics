"""Unit tests for authentication_analyzer.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from email_parser import parse_email
from authentication_analyzer import analyze_authentication


def _make_email(auth_results: str, extra_headers: str = "") -> str:
    return f"""\
From: sender@example.com
To: recipient@example.com
Subject: Test
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <test@example.com>
Authentication-Results: mx.example.com;
 {auth_results}
{extra_headers}
Content-Type: text/plain

Body text.
"""


class TestAuthenticationAnalyzer:
    def test_all_pass(self):
        email = _make_email("spf=pass; dkim=pass; dmarc=pass")
        parsed = parse_email(email)
        result = analyze_authentication(parsed)
        assert result.spf == "PASS"
        assert result.dkim == "PASS"
        assert result.dmarc == "PASS"
        assert result.all_passed is True
        assert result.any_failed is False

    def test_spf_fail_dmarc_fail(self):
        email = _make_email("spf=fail; dkim=pass; dmarc=fail")
        parsed = parse_email(email)
        result = analyze_authentication(parsed)
        assert result.spf == "FAIL"
        assert result.dkim == "PASS"
        assert result.dmarc == "FAIL"
        assert result.any_failed is True
        assert result.all_passed is False

    def test_spf_softfail(self):
        email = _make_email("spf=softfail; dkim=pass; dmarc=fail")
        parsed = parse_email(email)
        result = analyze_authentication(parsed)
        assert result.spf == "SOFTFAIL"
        assert result.any_failed is True

    def test_no_auth_header_returns_unknown(self):
        raw = """\
From: sender@example.com
To: recipient@example.com
Subject: No Auth
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <noauth@example.com>
Content-Type: text/plain

Body.
"""
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)
        assert result.spf == "UNKNOWN"
        assert result.dkim == "UNKNOWN"
        assert result.dmarc == "UNKNOWN"

    def test_received_spf_fallback(self):
        raw = """\
From: sender@example.com
To: recipient@example.com
Subject: SPF Fallback
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <spf@example.com>
Received-SPF: pass (sender is authorized)
Content-Type: text/plain

Body.
"""
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)
        assert result.spf == "PASS"

    def test_summary_contains_protocol_names(self):
        email = _make_email("spf=pass; dkim=fail; dmarc=fail")
        parsed = parse_email(email)
        result = analyze_authentication(parsed)
        # Summary should mention at least one protocol name from the failures
        assert any(proto in result.summary for proto in ("SPF", "DKIM", "DMARC"))

    def test_pass_does_not_guarantee_safety_note(self):
        email = _make_email("spf=pass; dkim=pass; dmarc=pass")
        parsed = parse_email(email)
        result = analyze_authentication(parsed)
        # The summary must include a caveat that PASS ≠ safe
        assert "does NOT guarantee" in result.summary or "not guarantee" in result.summary.lower()

    def test_none_result_not_malicious(self):
        email = _make_email("spf=none; dkim=none; dmarc=none")
        parsed = parse_email(email)
        result = analyze_authentication(parsed)
        assert result.spf == "NONE"
        assert result.any_failed is False
