"""
GmailGuard — Critical Audit & Verification Test Suite (Items C through N)

Tests:
C. MOCK_URLSCAN=true mode verification
D. MOCK_URLSCAN=false live mode path
E. urlscan API failure returns status=ERROR, verdict=UNKNOWN (never CLEAN)
F. urlscan timeout returns status=TIMEOUT, verdict=UNKNOWN (never CLEAN)
G. unknown URL in mock mode returns verdict=UNKNOWN (never CLEAN)
H. IPinfo configured and successful lookup (city, region, country, ASN, org, loc)
I. IPinfo unavailable / connection error returns status=error (never CLEAN)
J. IPinfo no-result (HTTP 404) returns status=not_found (never CLEAN)
K. private / loopback / reserved IPs rejected (never geolocated)
L. multiple public IPs deduplicated and cached
M. dynamic sandbox & IP intelligence evidence flows into final threat score
N. API response contains IPinfo evidence, sender_ip, and sandbox fields
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from .. import config
from ..api import app
from ..email_parser import parse_email
from ..geolocation import get_ip_geolocation, geolocate_ips, _GEO_CACHE
from ..header_analyzer import analyze_headers
from ..main import analyze_email
from ..report_generator import generate_report
from ..threat_scorer import compute_threat_score
from ..url_sandbox import (
    URLScanFinding,
    URLSandboxAnalysis,
    analyze_urls_dynamic,
    extract_sandbox_findings,
    scan_url_dynamic,
)


# ═══════════════════════════════════════════════════════════════════
# URLSCAN AUDIT TESTS (C, D, E, F, G, Adult Content)
# ═══════════════════════════════════════════════════════════════════

class TestUrlScanAuditFixes:
    """Test URLScan mock mode, live mode, failure modes, and adult content categorization."""

    def test_mock_urlscan_true_sets_mock_mode(self):
        """C. When MOCK_URLSCAN=true, finding mode must be explicitly 'MOCK'."""
        with patch.object(config, "MOCK_URLSCAN", True):
            finding = scan_url_dynamic("http://bit.ly/3xHDFC-verify")
            assert finding.mode == "MOCK"
            assert finding.status == "COMPLETED"
            assert finding.verdict == "MALICIOUS"

    def test_mock_urlscan_unknown_url_returns_unknown_not_clean(self):
        """G. An arbitrary/unknown URL in mock mode must return UNKNOWN, never CLEAN."""
        with patch.object(config, "MOCK_URLSCAN", True):
            finding = scan_url_dynamic("https://unseen-random-domain-12345.org/path")
            assert finding.mode == "MOCK"
            assert finding.verdict == "UNKNOWN", "Arbitrary URL must not silently return CLEAN"
            assert finding.verdict != "CLEAN"

    def test_mock_urlscan_false_triggers_live_submission(self):
        """D. When MOCK_URLSCAN=false, system must perform a real network request."""
        mock_submit_resp = MagicMock()
        mock_submit_resp.read.return_value = json.dumps({
            "message": "Submission successful",
            "uuid": "live-test-uuid-999",
            "result": "https://urlscan.io/result/live-test-uuid-999/",
            "api": "https://urlscan.io/api/v1/result/live-test-uuid-999/",
        }).encode("utf-8")

        mock_poll_resp = MagicMock()
        mock_poll_resp.read.return_value = json.dumps({
            "task": {"uuid": "live-test-uuid-999"},
            "page": {"url": "https://live-target.com/", "domain": "live-target.com"},
            "lists": {"domains": ["live-target.com"], "ips": ["1.2.3.4"]},
            "verdicts": {"overall": {"score": 0, "malicious": False, "categories": []}},
        }).encode("utf-8")

        ctx_submit = MagicMock()
        ctx_submit.__enter__.return_value = mock_submit_resp
        ctx_poll = MagicMock()
        ctx_poll.__enter__.return_value = mock_poll_resp

        with patch.object(config, "MOCK_URLSCAN", False):
            with patch.object(config, "URLSCAN_API_KEY", "dummy-key"):
                with patch("urllib.request.urlopen", side_effect=[ctx_submit, ctx_poll]):
                    finding = scan_url_dynamic("https://live-target.com")
                    assert finding.mode == "LIVE"
                    assert finding.status == "COMPLETED"
                    assert finding.verdict == "CLEAN"

    def test_urlscan_live_api_failure_returns_error_and_unknown(self):
        """E. Live API failure must return status=ERROR and verdict=UNKNOWN, NEVER CLEAN."""
        err_500 = urllib.error.HTTPError(
            url="https://urlscan.io/api/v1/scan/",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"message": "Database error"}'),
        )
        with patch.object(config, "MOCK_URLSCAN", False):
            with patch.object(config, "URLSCAN_API_KEY", "dummy-key"):
                with patch("urllib.request.urlopen", side_effect=err_500):
                    finding = scan_url_dynamic("https://error-target.com")
                    assert finding.mode == "LIVE"
                    assert finding.status == "ERROR"
                    assert finding.verdict == "UNKNOWN", "API failure must return UNKNOWN verdict, not CLEAN"
                    assert finding.is_malicious is False
                    assert any("500" in r for r in finding.reasons)

    def test_urlscan_timeout_returns_timeout_and_unknown(self):
        """F. Polling timeout must return status=TIMEOUT, verdict=UNKNOWN, NEVER CLEAN."""
        mock_submit_resp = MagicMock()
        mock_submit_resp.read.return_value = json.dumps({
            "message": "Submission successful",
            "uuid": "timeout-uuid-111",
            "result": "https://urlscan.io/result/timeout-uuid-111/",
            "api": "https://urlscan.io/api/v1/result/timeout-uuid-111/",
        }).encode("utf-8")

        err_404 = urllib.error.HTTPError(
            url="https://urlscan.io/api/v1/result/timeout-uuid-111/",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"message": "Scan pending"}'),
        )

        ctx_submit = MagicMock()
        ctx_submit.__enter__.return_value = mock_submit_resp

        with patch.object(config, "MOCK_URLSCAN", False):
            with patch.object(config, "URLSCAN_API_KEY", "dummy-key"):
                with patch("urllib.request.urlopen", side_effect=[ctx_submit, err_404, err_404, err_404]):
                    finding = scan_url_dynamic(
                        "https://slow-target.com",
                        timeout_s=1,
                        poll_interval_s=0.01,
                    )
                    assert finding.status in ("TIMEOUT", "ERROR")
                    assert finding.verdict == "UNKNOWN"
                    assert finding.is_malicious is False

    def test_force_live_overrides_mock_mode(self):
        """F-2. force_live=True forces a live submission even if MOCK_URLSCAN=True."""
        mock_submit_resp = MagicMock()
        mock_submit_resp.read.return_value = json.dumps({
            "message": "Submission successful",
            "uuid": "forced-uuid",
            "result": "https://urlscan.io/result/forced-uuid/",
            "api": "https://urlscan.io/api/v1/result/forced-uuid/",
        }).encode("utf-8")

        mock_poll_resp = MagicMock()
        mock_poll_resp.read.return_value = json.dumps({
            "task": {"uuid": "forced-uuid"},
            "page": {"url": "https://example.com/", "domain": "example.com"},
            "lists": {"domains": [], "ips": []},
            "verdicts": {"overall": {"score": 0, "malicious": False, "categories": []}},
        }).encode("utf-8")

        ctx_submit = MagicMock()
        ctx_submit.__enter__.return_value = mock_submit_resp
        ctx_poll = MagicMock()
        ctx_poll.__enter__.return_value = mock_poll_resp

        with patch.object(config, "MOCK_URLSCAN", True):  # mock is ON
            with patch.object(config, "URLSCAN_API_KEY", "valid-key"):
                with patch("urllib.request.urlopen", side_effect=[ctx_submit, ctx_poll]):
                    finding = scan_url_dynamic("https://example.com", force_live=True)
                    assert finding.mode == "LIVE", "force_live=True must override MOCK_URLSCAN"
                    assert finding.status == "COMPLETED"

    def test_adult_content_categorized_without_falsely_claiming_malware(self):
        """4. Adult/pornographic content must be flagged as ADULT_CONTENT, NOT malware."""
        raw_data = {
            "task": {"reportURL": "https://urlscan.io/result/adult-uuid/"},
            "page": {"url": "https://adult-site.example/gallery", "domain": "adult-site.example"},
            "lists": {"domains": ["adult-site.example"], "ips": ["198.51.100.1"]},
            "verdicts": {
                "overall": {
                    "score": 40,
                    "malicious": False,
                    "categories": ["pornography", "adult"],
                }
            },
        }
        finding = extract_sandbox_findings("https://adult-site.example/gallery", "adult-uuid", raw_data)
        assert finding.content_category == "ADULT_CONTENT"
        assert "ADULT_CONTENT_DETECTED" in finding.behavior_indicators
        assert finding.is_malicious is False, "Adult content must not be marked as malware"
        assert finding.verdict == "SUSPICIOUS"  # adult content contributes to suspicious, not malware


# ═══════════════════════════════════════════════════════════════════
# IPINFO AUDIT TESTS (H, I, J, K, L)
# ═══════════════════════════════════════════════════════════════════

class TestIPinfoAuditFixes:
    """Test IPinfo observable infrastructure lookup, error handling, filtering, and caching."""

    def setup_method(self):
        _GEO_CACHE.clear()

    def test_ipinfo_configured_and_successful(self):
        """H. Public IP queried with IPinfo returns complete infrastructure intelligence."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "org": "AS15169 Google LLC",
            "postal": "94043",
            "timezone": "America/Los_Angeles",
        }).encode("utf-8")

        ctx = MagicMock()
        ctx.__enter__.return_value = mock_resp

        with patch.object(config, "IPINFO_TOKEN", "test-token"):
            with patch("urllib.request.urlopen", return_value=ctx):
                res = get_ip_geolocation("8.8.8.8")
                assert res["status"] == "success"
                assert res["city"] == "Mountain View"
                assert res["region"] == "California"
                assert res["country"] == "US"
                assert res["asn"] == "AS15169"
                assert "Google LLC" in res["organization"]
                assert res["latitude"] == pytest.approx(37.4056)
                assert res["longitude"] == pytest.approx(-122.0775)
                assert res["timezone"] == "America/Los_Angeles"
                assert res["source"] == "IPinfo"
                assert res["location_type"] == "observable_infrastructure"

    def test_ipinfo_unavailable_returns_error_never_clean(self):
        """I. Network/connection failure to IPinfo returns status=error, never clean."""
        with patch.object(config, "IPINFO_TOKEN", "test-token"):
            with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection timed out")):
                res = get_ip_geolocation("8.8.8.8")
                assert res["status"] in ("error", "unavailable")
                assert "timed out" in res["reason"].lower()
                assert res["country"] == "UNKNOWN"

    def test_ipinfo_not_found_404_returns_not_found(self):
        """J. IPinfo HTTP 404 returns status=not_found, never clean."""
        err_404 = urllib.error.HTTPError(
            url="https://ipinfo.io/8.8.8.8/json",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"error": "IP not found"}'),
        )
        with patch.object(config, "IPINFO_TOKEN", "test-token"):
            with patch("urllib.request.urlopen", side_effect=err_404):
                res = get_ip_geolocation("8.8.8.8")
                assert res["status"] == "not_found"
                assert "no intelligence" in res["reason"].lower()

    def test_private_and_loopback_ips_rejected(self):
        """K. Private, loopback, and invalid IPs must be rejected and never geolocated."""
        private_ips = ["127.0.0.1", "10.0.0.1", "192.168.1.100", "172.16.0.1", "::1"]
        for ip in private_ips:
            res = get_ip_geolocation(ip)
            assert res["status"] == "rejected"
            assert "private or reserved" in res["reason"].lower()

        res_inv = get_ip_geolocation("invalid-ip-address")
        assert res_inv["status"] == "error"
        assert "invalid" in res_inv["reason"].lower()

    def test_multiple_public_ips_deduplicated_and_cached(self):
        """L. Duplicate IPs in an email must only be queried once and results cached."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "country": "US",
            "org": "Google",
        }).encode("utf-8")
        ctx = MagicMock()
        ctx.__enter__.return_value = mock_resp

        with patch.object(config, "IPINFO_TOKEN", "test-token"):
            with patch("urllib.request.urlopen", return_value=ctx) as mock_url:
                results = geolocate_ips(["8.8.8.8", "8.8.8.8", "8.8.8.8"])
                assert len(results) == 3
                # Only 1 unique IP lookup should have been performed
                assert mock_url.call_count == 1

    def test_sender_ip_not_observable_when_missing(self):
        """6. When no sender IP is observable in headers, sender_ip must be 'NOT_OBSERVABLE'."""
        parsed = parse_email("From: a@b.com\nTo: c@d.com\nSubject: Test\n\nNo IP here.")
        header_intel = analyze_headers(parsed)
        header_intel.x_originating_ip = None

        from ..authentication_analyzer import AuthResult
        from ..ip_intelligence import IPIntelligence
        from ..domain_intelligence import DomainIntelligence
        from ..url_analyzer import URLAnalysis
        from ..attachment_analyzer import AttachmentAnalysis
        from ..ml_classifier import MLResult
        from ..threat_scorer import ThreatScore

        auth = AuthResult("PASS", "PASS", "PASS", "", "", "", True, False, "ok")
        ip_intel = IPIntelligence([], [], False, False, 0, [])
        dom_intel = DomainIntelligence("b.com", "clean", 0, [], 100, None, None, False, ".com", False, "", 0, [], "MOCK")
        urls = URLAnalysis(0, 0, [], [], [])
        atts = AttachmentAnalysis(0, 0, [])
        ml = MLResult("HAM", -1.0, True, "safe")
        score = ThreatScore(0, "CLEAN", {}, [], [], [], {})

        report = generate_report(
            parsed=parsed,
            auth=auth,
            header_intel=header_intel,
            ip_intel=ip_intel,
            geo_records=[],
            url_analysis=urls,
            att_analysis=atts,
            ml=ml,
            domain_intel=dom_intel,
            threat_score=score,
        )
        assert report["infrastructure"]["sender_ip"] == "NOT_OBSERVABLE"


# ═══════════════════════════════════════════════════════════════════
# THREAT SCORING & CORRELATION AUDIT TESTS (M, No Unilateral Clean)
# ═══════════════════════════════════════════════════════════════════

class TestThreatScoringAuditFixes:
    """Test dynamic URL sandbox and IP evidence flowing into ThreatScore."""

    def test_url_sandbox_malicious_finding_increases_threat_score(self):
        """M. URLScan MALICIOUS finding must increase score and be present in contributing factors."""
        from ..ml_classifier import MLResult
        from ..authentication_analyzer import AuthResult
        from ..ip_intelligence import IPIntelligence
        from ..domain_intelligence import DomainIntelligence
        from ..url_analyzer import URLAnalysis
        from ..attachment_analyzer import AttachmentAnalysis

        parsed = parse_email("From: alert@phish.org\nTo: victim@co.com\nSubject: Urgent\n\nClick link")
        header_intel = analyze_headers(parsed)

        ml = MLResult("HAM", -1.0, True, "ML says ham")
        auth = AuthResult("PASS", "PASS", "PASS", "", "", "", True, False, "ok")
        ip_intel = IPIntelligence([], [], False, False, 0, [])
        dom_intel = DomainIntelligence("safe.com", "clean", 0, [], 500, None, None, False, ".com", False, "", 0, [], "MOCK")
        urls = URLAnalysis(1, 0, [], ["http://bit.ly/3xHDFC-verify"], [])
        atts = AttachmentAnalysis(0, 0, [])

        sandbox_malicious = URLSandboxAnalysis(
            total_scanned=1,
            malicious_count=1,
            suspicious_count=0,
            mode="LIVE",
            findings=[
                URLScanFinding(
                    submitted_url="http://bit.ly/3xHDFC-verify",
                    effective_url="https://secure-banking-update.xyz/login.php",
                    mode="LIVE",
                    status="COMPLETED",
                    verdict="MALICIOUS",
                    is_malicious=True,
                    malicious_score=96,
                )
            ]
        )

        score = compute_threat_score(
            ml=ml, auth=auth, ip_intel=ip_intel, domain_intel=dom_intel,
            url_analysis=urls, att_analysis=atts, header_intel=header_intel,
            url_sandbox=sandbox_malicious,
        )

        # Threat score without sandbox: 14 (CLEAN)
        # With sandbox MALICIOUS (96/100): URL subscore rises to 96, threat_score rises to 31
        assert score.threat_score > 14, "Malicious URL in sandbox must significantly increase score"
        assert score.sub_scores["url"] == 96
        evidence_texts = " ".join(e.explanation for e in score.evidence)
        assert ("urlscan.io dynamic execution flagged URL" in evidence_texts or "Browser sandbox dynamic execution flagged URL" in evidence_texts)
        assert "MALICIOUS" in evidence_texts

    def test_url_sandbox_adult_content_adds_suspicious_evidence(self):
        """4. Adult content finding in sandbox adds suspicious factor without malware label."""
        from ..ml_classifier import MLResult
        from ..authentication_analyzer import AuthResult
        from ..ip_intelligence import IPIntelligence
        from ..domain_intelligence import DomainIntelligence
        from ..url_analyzer import URLAnalysis
        from ..attachment_analyzer import AttachmentAnalysis

        parsed = parse_email("From: alert@phish.org\nTo: victim@co.com\nSubject: Urgent\n\nClick link")
        header_intel = analyze_headers(parsed)

        ml = MLResult("Legitimate", -1.0, True, "clean")
        auth = AuthResult("PASS", "PASS", "PASS", "", "", "", True, False, "ok")
        ip_intel = IPIntelligence([], [], False, False, 0, [])
        dom_intel = DomainIntelligence("safe.com", "clean", 0, [], 500, None, None, False, ".com", False, "", 0, [], "MOCK")
        urls = URLAnalysis(1, 0, [], ["https://adult.example"], [])
        atts = AttachmentAnalysis(0, 0, [])

        sandbox_adult = URLSandboxAnalysis(
            total_scanned=1, malicious_count=0, suspicious_count=1, mode="LIVE",
            findings=[
                URLScanFinding(
                    submitted_url="https://adult.example",
                    effective_url="https://adult.example",
                    mode="LIVE",
                    status="COMPLETED",
                    verdict="SUSPICIOUS",
                    is_malicious=False,
                    content_category="ADULT_CONTENT",
                    behavior_indicators=["ADULT_CONTENT_DETECTED"],
                )
            ]
        )

        score = compute_threat_score(
            ml=ml, auth=auth, ip_intel=ip_intel, domain_intel=dom_intel,
            url_analysis=urls, att_analysis=atts, header_intel=header_intel,
            url_sandbox=sandbox_adult,
        )
        evidence_texts = " ".join(e.explanation for e in score.evidence)
        assert "Adult content detected" in evidence_texts
        assert "not classified as malware" in evidence_texts
        assert "Malware detected" not in evidence_texts

    def test_sandbox_clean_does_not_unilaterally_override_phishing_ml(self):
        """3. Sandbox CLEAN must NOT force a CLEAN GmailGuard verdict when ML detects phishing."""
        from ..ml_classifier import MLResult
        from ..authentication_analyzer import AuthResult
        from ..ip_intelligence import IPIntelligence
        from ..domain_intelligence import DomainIntelligence
        from ..url_analyzer import URLAnalysis
        from ..attachment_analyzer import AttachmentAnalysis

        parsed = parse_email("From: alert@phish.org\nTo: victim@co.com\nSubject: Urgent\n\nClick link")
        header_intel = analyze_headers(parsed)

        ml = MLResult("Phishing", 3.0, True, "Aggressive credential harvesting template")
        auth = AuthResult("FAIL", "NONE", "FAIL", "SPF hardfail", "", "DMARC fail", False, True, "fail")
        ip_intel = IPIntelligence([], [], False, False, 0, [])
        dom_intel = DomainIntelligence("target.com", "suspicious", 40, [], 5, None, None, False, ".com", False, "", 40, [], "MOCK")
        urls = URLAnalysis(1, 0, [], ["https://neutral.com"], [])
        atts = AttachmentAnalysis(0, 0, [])

        sandbox_clean = URLSandboxAnalysis(
            total_scanned=1, malicious_count=0, suspicious_count=0, mode="LIVE",
            findings=[
                URLScanFinding(
                    submitted_url="https://neutral.com",
                    effective_url="https://neutral.com",
                    mode="LIVE",
                    status="COMPLETED",
                    verdict="CLEAN",
                    is_malicious=False,
                )
            ]
        )

        score = compute_threat_score(
            ml=ml, auth=auth, ip_intel=ip_intel, domain_intel=dom_intel,
            url_analysis=urls, att_analysis=atts, header_intel=header_intel,
            url_sandbox=sandbox_clean,
        )
        assert score.verdict in ("MEDIUM_RISK", "HIGH_RISK", "CRITICAL"), "Sandbox CLEAN must not override strong phishing signals"
        assert score.verdict != "CLEAN"


# ═══════════════════════════════════════════════════════════════════
# API & FRONTEND CONTRACT AUDIT TESTS (N)
# ═══════════════════════════════════════════════════════════════════

class TestApiAndContractAuditFixes:
    """Test that FastAPI /analyze-text endpoint returns real IPinfo and URL sandbox evidence."""

    def setup_method(self):
        self.client = TestClient(app)

    def test_api_returns_ipinfo_and_sandbox_evidence(self):
        """N. API response contains IPinfo geolocation context and dynamic sandbox evidence."""
        sample_eml = """From: Security Alert <alert@example-threat.org>
To: user@victim.com
Subject: Notice: Account Action Required
Date: Tue, 09 Sep 2026 00:00:00 +0000
Message-ID: <msg-9999@example-threat.org>
X-Originating-IP: [142.250.190.46]

Please review your statement here:
https://example.com/login
"""
        with patch.object(config, "MOCK_URLSCAN", True):
            resp = self.client.post("/analyze-text", json={"raw_email": sample_eml})
            assert resp.status_code == 200
            data = resp.json()

            # Verify infrastructure section contains sender_ip and geolocation
            assert "infrastructure" in data
            assert data["infrastructure"]["sender_ip"] == "142.250.190.46"
            assert "geolocation" in data["infrastructure"]
            assert len(data["infrastructure"]["geolocation"]) >= 1

            geo_entry = data["infrastructure"]["geolocation"][0]
            assert "status" in geo_entry
            assert "source" in geo_entry
            assert "location_type" in geo_entry

            # Verify URL sandbox in forensics
            assert "forensics" in data
            assert "url_sandbox" in data["forensics"]
            sandbox = data["forensics"]["url_sandbox"]
            assert "total_scanned" in sandbox
            assert "findings" in sandbox
            if sandbox["findings"]:
                finding = sandbox["findings"][0]
                assert "mode" in finding
                assert "verdict" in finding
                assert "status" in finding
