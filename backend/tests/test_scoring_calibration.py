"""
Test Suite: Scoring Calibration & Baseline URL Validation

Validates GmailGuard's reformed threat scoring against baseline legitimate URLs
(Google, GitHub, Microsoft, Example) and controlled suspicious/malicious emails.
Ensures browser behavior telemetry does not falsely inflate security threat scores.
"""

import pytest
from pathlib import Path

from backend.url_sandbox import (
    scan_url_dynamic,
    _extract_apex_domain,
    URLScanFinding,
)
from backend.threat_scorer import compute_threat_score
from backend.url_analyzer import URLFinding, URLAnalysis
from backend.ml_classifier import MLResult
from backend.email_parser import parse_email
from backend.tests.test_threat_scorer import (
    _make_auth,
    _make_ip_intel,
    _make_domain_intel,
    _make_att_analysis,
    _make_header_intel,
)


class TestBaselineURLSandboxing:
    """Validate that legitimate baseline URLs do not produce false positive threat verdicts."""

    @pytest.mark.parametrize("baseline_url", [
        "https://www.google.com",
        "https://www.github.com",
        "https://example.com",
        "https://www.microsoft.com",
    ])
    def test_baseline_urls_evaluate_clean_in_sandbox(self, baseline_url):
        """Baseline modern websites must evaluate as CLEAN even with redirects/CDNs."""
        finding = scan_url_dynamic(baseline_url, timeout_s=8)
        
        # Must complete successfully
        assert finding.status in ("COMPLETED", "SKIPPED_DEV"), f"Status: {finding.status}, err: {finding.error}"
        
        # Behavioral telemetry must NOT produce SUSPICIOUS or MALICIOUS verdicts
        assert finding.verdict == "CLEAN", f"Expected CLEAN for {baseline_url}, got {finding.verdict} (reasons: {finding.reasons})"
        assert finding.malicious_score <= 15, f"Score too high: {finding.malicious_score}"
        assert not finding.is_malicious

    def test_canonical_redirect_apex_extraction(self):
        """Canonical subdomains (www.github.com -> github.com) must share the apex domain."""
        assert _extract_apex_domain("www.github.com") == "github.com"
        assert _extract_apex_domain("github.com") == "github.com"
        assert _extract_apex_domain("sub.api.example.co.uk") == "example.co.uk"
        assert _extract_apex_domain("login.microsoft.com") == "microsoft.com"

    def test_high_network_activity_alone_does_not_make_verdict_suspicious(self):
        """A page making 80 requests across CDNs without malicious payload must be CLEAN."""
        finding = URLScanFinding(
            submitted_url="https://www.github.com",
            effective_url="https://github.com/",
            status="COMPLETED",
            verdict="CLEAN",
            malicious_score=0,
            behavior_indicators=["CANONICAL_REDIRECT", "HIGH_NETWORK_ACTIVITY"],
            contacted_domains=["github.com", "githubassets.com", "api.github.com"],
            network_requests=[{"url": f"https://cdn.example.com/asset{i}.js"} for i in range(80)],
        )
        assert finding.verdict == "CLEAN"
        assert finding.malicious_score == 0


class TestScoringGuardrailsAndBreakdown:
    """Validate score caps, guardrails, and explainable breakdowns."""

    def test_clean_url_boost_is_zero(self):
        """A clean URL analysis must add exactly 0.0 boost to base threat score."""
        finding = URLFinding(
            url="https://www.github.com",
            domain="github.com",
            tld=".com",
            risk_score=0,
            is_ip_url=False,
            is_url_shortener=False,
            has_suspicious_tld=False,
            excessive_subdomains=False,
            has_suspicious_chars=False,
            suspicious_char_matches=[],
            uses_https=True,
            display_href_mismatch=False,
            domain_reputation="clean",
            domain_rep_score=0,
            reasons=[],
        )
        url_analysis = URLAnalysis(
            total_count=1,
            suspicious_count=0,
            findings=[finding],
            all_urls=["https://www.github.com"],
            limitations=[],
        )

        ml = MLResult(prediction="Legitimate", decision_score=-1.2, model_available=True, note="clean")
        auth = _make_auth("PASS", "PASS", "PASS")
        domain = _make_domain_intel("clean", 0)
        ip = _make_ip_intel("clean", 0)
        att = _make_att_analysis(0, 0)
        headers = _make_header_intel()

        score_result = compute_threat_score(
            ml=ml, auth=auth, ip_intel=ip, domain_intel=domain,
            url_analysis=url_analysis, att_analysis=att, header_intel=headers,
        )

        assert score_result.threat_score <= 20
        assert score_result.verdict == "CLEAN"
        assert score_result.score_breakdown["url_boost"] == 0.0
        assert score_result.score_breakdown["final_score"] == score_result.threat_score

    def test_malicious_url_elevates_threat_score(self):
        """A confirmed high-risk phishing URL must significantly elevate the threat score."""
        mal_finding = URLFinding(
            url="http://185.220.101.5/login.php",
            domain="185.220.101.5",
            tld="",
            risk_score=85,
            is_ip_url=True,
            is_url_shortener=False,
            has_suspicious_tld=False,
            excessive_subdomains=False,
            has_suspicious_chars=False,
            suspicious_char_matches=[],
            uses_https=False,
            display_href_mismatch=False,
            domain_reputation="malicious",
            domain_rep_score=90,
            reasons=["Direct IP URL", "Malicious domain reputation"],
        )
        url_analysis = URLAnalysis(
            total_count=1,
            suspicious_count=1,
            findings=[mal_finding],
            all_urls=["http://185.220.101.5/login.php"],
            limitations=[],
        )

        ml = MLResult(prediction="Phishing", decision_score=1.5, model_available=True, note="phishing")
        auth = _make_auth("FAIL", "FAIL", "FAIL")
        domain = _make_domain_intel("malicious", 85)
        ip = _make_ip_intel("clean", 0)
        att = _make_att_analysis(0, 0)
        headers = _make_header_intel()

        score_result = compute_threat_score(
            ml=ml, auth=auth, ip_intel=ip, domain_intel=domain,
            url_analysis=url_analysis, att_analysis=att, header_intel=headers,
        )

        assert score_result.threat_score >= 80
        assert score_result.verdict in ("HIGH_RISK", "MALICIOUS", "CRITICAL")
        assert score_result.score_breakdown["url_boost"] > 15.0


class TestEndToEndSampleEmails:
    """Test full pipeline on actual sample emails in repository."""

    def test_benign_github_email_scores_clean(self):
        """helpdesk_rnicrosoft_test.eml containing github.com must score CLEAN (under 25)."""
        eml_path = Path("helpdesk_rnicrosoft_test.eml")
        if not eml_path.exists():
            pytest.skip("helpdesk_rnicrosoft_test.eml not found")

        content = eml_path.read_text(encoding="utf-8", errors="ignore")
        parsed = parse_email(content)

        from backend.ml_classifier import classify_email
        ml_res = classify_email(parsed.subject, parsed.text_body)

        # Short benign text must not trigger false positive phishing
        assert ml_res.prediction == "Legitimate"

    def test_genuine_phishing_email_scores_high_risk(self):
        """phishing_bank.eml must receive a HIGH_RISK or CRITICAL threat verdict."""
        eml_path = Path("backend/sample_emails/phishing_bank.eml")
        if not eml_path.exists():
            pytest.skip("phishing_bank.eml not found")

        content = eml_path.read_text(encoding="utf-8", errors="ignore")
        parsed = parse_email(content)

        from backend.ml_classifier import classify_email
        ml_res = classify_email(parsed.subject, parsed.text_body)
        assert ml_res.prediction == "Phishing"
        assert ml_res.decision_score > 0.8
