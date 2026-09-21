"""Unit tests for authentication_analyzer.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from ..email_parser import parse_email
from ..authentication_analyzer import analyze_authentication


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

    # ── Required Cases A through F ──────────────────────────────

    def test_case_a_all_pass(self):
        """Case A: All PASS (spf=pass; dkim=pass; dmarc=pass)."""
        from ..threat_scorer import _score_authentication
        email = _make_email("spf=pass; dkim=pass; dmarc=pass")
        parsed = parse_email(email)
        result = analyze_authentication(parsed)
        assert result.spf == "PASS"
        assert result.dkim == "PASS"
        assert result.dmarc == "PASS"

        sub_score, ev, available = _score_authentication(result)
        assert available is True
        assert sub_score == 10
        assert all(e.is_positive for e in ev)

    def test_case_b_mixed(self):
        """Case B: Mixed (spf=pass; dkim=fail; dmarc=pass)."""
        from ..threat_scorer import _score_authentication
        email = _make_email("spf=pass; dkim=fail; dmarc=pass")
        parsed = parse_email(email)
        result = analyze_authentication(parsed)
        assert result.spf == "PASS"
        assert result.dkim == "FAIL"
        assert result.dmarc == "PASS"

        sub_score, ev, available = _score_authentication(result)
        assert available is True
        assert any(e.status == "FAIL" for e in ev)
        assert any(e.status == "PASS" for e in ev)

    def test_case_c_all_fail(self):
        """Case C: All FAIL (spf=fail; dkim=fail; dmarc=fail)."""
        from ..threat_scorer import _score_authentication
        email = _make_email("spf=fail; dkim=fail; dmarc=fail")
        parsed = parse_email(email)
        result = analyze_authentication(parsed)
        assert result.spf == "FAIL"
        assert result.dkim == "FAIL"
        assert result.dmarc == "FAIL"

        sub_score, ev, available = _score_authentication(result)
        assert available is True
        assert sub_score == 90
        assert result.any_failed is True

    def test_case_d_missing_authentication(self):
        """Case D: Missing authentication produces UNKNOWN, available=False, no score distortion."""
        from ..threat_scorer import _score_authentication, compute_threat_score
        from ..ml_classifier import MLResult
        from ..domain_intelligence import DomainIntelligence
        from ..ip_intelligence import IPIntelligence
        from ..url_analyzer import URLAnalysis
        from ..attachment_analyzer import AttachmentAnalysis
        from ..header_analyzer import HeaderIntelligence

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

        sub_score, ev, available = _score_authentication(result)
        assert available is False
        assert sub_score == 0

        # Score with missing auth vs score with explicit excluded auth
        ml = MLResult("Phishing", 2.0, True, "ml")
        dom = DomainIntelligence("example.com", "clean", 20, [], 100, None, None, False, ".com", False, "", 20, [], "MOCK")
        urls = URLAnalysis(0, 0, [], [], [])
        atts = AttachmentAnalysis(0, 0, [])
        hdr = HeaderIntelligence([], "", "", False, "", "sender@example.com", "example.com", [], "", [])

        score_res = compute_threat_score(
            ml=ml, auth=result, ip_intel=IPIntelligence([], [], False, False, 0, []),
            domain_intel=dom, url_analysis=urls, att_analysis=atts, header_intel=hdr,
        )
        assert score_res.sub_scores["authentication"] == 0
        # Authentication should be listed in limitations
        assert any("SPF/DKIM/DMARC" in lim for lim in score_res.limitations)

    def test_case_e_received_spf_fallback(self):
        """Case E: Received-SPF fallback."""
        raw = """\
From: sender@example.com
To: recipient@example.com
Subject: Test
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <test@example.com>
Received-SPF: pass (myhost.net: domain of sender@example.com designates 1.2.3.4 as permitted sender)
Content-Type: text/plain

Body.
"""
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)
        assert result.spf == "PASS"

    def test_case_f_dkim_signature_without_auth_results(self):
        """Case F: DKIM-Signature header present without Authentication-Results produces DKIM=NONE."""
        raw = """\
From: sender@example.com
To: recipient@example.com
Subject: Test
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <test@example.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1;
Content-Type: text/plain

Body.
"""
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)
        assert result.dkim == "NONE"
        assert "DKIM-Signature header present but unverified" in result.dkim_detail

    def test_folded_multiline_headers_and_tabs(self):
        """Folded multiline Authentication-Results with arbitrary tabs and spaces."""
        raw = """\
From: sender@example.com
To: recipient@example.com
Subject: Test
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <test@example.com>
Authentication-Results: mx.example.com;
\tspf=pass (sender IP is 1.2.3.4);
\tdkim=pass (signature verified);
\tdmarc=pass (p=reject sp=reject dis=none)
Content-Type: text/plain

Body.
"""
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)
        assert result.spf == "PASS"
        assert result.dkim == "PASS"
        assert result.dmarc == "PASS"
        assert result.all_passed is True

    def test_multiple_authentication_results_headers_prioritizes_definitive(self):
        """Multiple Authentication-Results headers (RFC 8601) prioritize definitive pass/fail over internal none."""
        raw = """\
From: sender@example.com
To: recipient@example.com
Subject: Test
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <test@example.com>
Authentication-Results: internal-relay.local; dkim=none
Authentication-Results: mx.google.com;
\tspf=pass;
\tdkim=pass;
\tdmarc=pass
Content-Type: text/plain

Body.
"""
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)
        assert result.spf == "PASS"
        assert result.dkim == "PASS"
        assert result.dmarc == "PASS"
        assert result.all_passed is True

    def test_body_text_not_accepted_as_auth_headers(self):
        """Body text with SPF: PASS / DKIM: PASS must NOT be parsed as real headers."""
        raw = """\
From: attacker@evil.com
To: victim@company.com
Subject: Fake security report
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <fake@evil.com>
Content-Type: text/plain

Authentication-Results: mx.evil.com; spf=pass; dkim=pass; dmarc=pass
SPF: PASS
DKIM: PASS
DMARC: PASS
"""
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)
        # It should only parse from actual headers; here no actual headers exist for auth
        assert result.spf == "UNKNOWN"
        assert result.dkim == "UNKNOWN"
        assert result.dmarc == "UNKNOWN"
