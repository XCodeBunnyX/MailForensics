"""Unit tests for url_analyzer.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from ..url_analyzer import analyze_urls, _analyze_single_url


class TestURLAnalyzer:
    def test_no_urls_returns_zero_count(self):
        result = analyze_urls("Hello, no links here.", "")
        assert result.total_count == 0
        assert result.suspicious_count == 0

    def test_ip_url_detected(self):
        result = analyze_urls("Click: http://185.234.219.47/phish", "")
        assert result.total_count >= 1
        finding = result.findings[0]
        assert finding.is_ip_url is True
        assert finding.risk_score > 0

    def test_url_shortener_detected(self):
        result = analyze_urls("Go here: https://bit.ly/abc123", "")
        finding = next((f for f in result.findings if f.is_url_shortener), None)
        assert finding is not None

    def test_suspicious_tld_detected(self):
        finding = _analyze_single_url("http://malicious-site.xyz/login")
        assert finding.has_suspicious_tld is True
        assert finding.risk_score > 0

    def test_http_not_https_flagged(self):
        finding = _analyze_single_url("http://example.com/page")
        assert finding.uses_https is False

    def test_https_not_flagged_as_http(self):
        finding = _analyze_single_url("https://github.com/user/repo")
        assert finding.uses_https is True

    def test_display_href_mismatch(self):
        html = '<a href="http://evil.xyz/steal">http://www.paypal.com/login</a>'
        result = analyze_urls("", html)
        mismatch_findings = [f for f in result.findings if f.display_href_mismatch]
        assert len(mismatch_findings) >= 1

    def test_html_url_extraction(self):
        html = '<a href="https://github.com/repo">Check it out</a>'
        result = analyze_urls("", html)
        assert result.total_count >= 1
        assert any("github.com" in f.domain for f in result.findings)

    def test_no_http_requests_made(self):
        # If analyze_urls makes network requests, this would be slow or fail.
        # It should complete instantly (well under 1 second).
        import time
        start = time.time()
        analyze_urls(
            "http://this-does-not-exist.invalid/page http://another.invalid/test",
            ""
        )
        elapsed = time.time() - start
        assert elapsed < 5.0, "URL analyzer should not make network requests"

    def test_clean_url_low_score(self):
        finding = _analyze_single_url("https://www.google.com/search?q=email+security")
        # Google should be very low risk
        assert finding.risk_score < 30

    def test_excessive_subdomains(self):
        finding = _analyze_single_url("http://a.b.c.d.evil.com/login")
        assert finding.excessive_subdomains is True
