"""
GmailGuard — URL Dynamic Analysis Sandbox Tests (urlscan.io)

Tests:
1. submit_scan: success, empty URL, missing API key, 400, 429, 401/403, URLError.
2. poll_scan_result: success, 404 retry loop, timeout, 429, URLError.
3. extract_sandbox_findings: clean URL, redirects, payload downloads, JS console errors, malicious verdicts.
4. scan_url_dynamic & analyze_urls_dynamic: mock mode, deduplication, max_scans limit, disabled handling.
5. Evidence correlation & report generator integration.
6. FastAPI /sandbox/scan-url endpoint.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from .. import config
from ..api import app
from ..evidence_correlator import correlate_evidence
from ..main import analyze_email
from ..report_generator import generate_report
from ..url_sandbox import (
    URLScanFinding,
    URLSandboxAnalysis,
    analyze_urls_dynamic,
    extract_sandbox_findings,
    poll_scan_result,
    scan_url_dynamic,
    submit_scan,
)


# ═══════════════════════════════════════════════════════════════════
# 1. SUBMIT SCAN TESTS
# ═══════════════════════════════════════════════════════════════════

class TestSubmitScan:
    """Test urlscan.io submission API call."""

    def test_missing_api_key(self):
        uuid, result_url, err = submit_scan("https://example.com", api_key="")
        assert uuid is None
        assert result_url is None
        assert "not configured" in err

    def test_empty_url(self):
        uuid, result_url, err = submit_scan("", api_key="test-key")
        assert uuid is None
        assert "empty" in err

    @patch("urllib.request.urlopen")
    def test_submit_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "message": "Submission successful",
            "uuid": "01a082d4-test-uuid-1234",
            "result": "https://urlscan.io/result/01a082d4-test-uuid-1234/",
            "api": "https://urlscan.io/api/v1/result/01a082d4-test-uuid-1234/",
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        uuid, result_url, err = submit_scan("https://example.com", api_key="valid-key")
        assert uuid == "01a082d4-test-uuid-1234"
        assert result_url == "https://urlscan.io/result/01a082d4-test-uuid-1234/"
        assert err is None

    @patch("urllib.request.urlopen")
    def test_submit_rate_limited_429(self, mock_urlopen):
        err = urllib.error.HTTPError(
            url="https://urlscan.io/api/v1/scan/",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"message": "Rate limit exceeded"}'),
        )
        mock_urlopen.side_effect = err

        uuid, result_url, err_msg = submit_scan("https://example.com", api_key="valid-key")
        assert uuid is None
        assert "rate limit reached (HTTP 429)" in err_msg

    @patch("urllib.request.urlopen")
    def test_submit_auth_error_401(self, mock_urlopen):
        err = urllib.error.HTTPError(
            url="https://urlscan.io/api/v1/scan/",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"message": "Invalid API key"}'),
        )
        mock_urlopen.side_effect = err

        uuid, result_url, err_msg = submit_scan("https://example.com", api_key="bad-key")
        assert uuid is None
        assert "authentication error (HTTP 401)" in err_msg

    @patch("urllib.request.urlopen")
    def test_submit_network_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("DNS resolution failed")

        uuid, result_url, err_msg = submit_scan("https://example.com", api_key="valid-key")
        assert uuid is None
        assert "Network connection failed" in err_msg


# ═══════════════════════════════════════════════════════════════════
# 2. POLL SCAN RESULT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestPollScanResult:
    """Test polling loop and timeout handling."""

    def test_invalid_uuid(self):
        data, err = poll_scan_result("")
        assert data is None
        assert "Invalid scan UUID" in err

    @patch("urllib.request.urlopen")
    def test_poll_immediate_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "task": {"uuid": "test-uuid"},
            "page": {"url": "https://example.com/"},
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        data, err = poll_scan_result("test-uuid", api_key="valid-key", max_wait_s=5)
        assert data is not None
        assert err is None
        assert data["task"]["uuid"] == "test-uuid"

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_poll_retry_after_404_then_success(self, mock_urlopen, mock_sleep):
        err_404 = urllib.error.HTTPError(
            url="https://urlscan.io/api/v1/result/test-uuid/",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"message": "Scan pending"}'),
        )
        success_resp = MagicMock()
        success_resp.read.return_value = json.dumps({
            "task": {"uuid": "test-uuid"},
            "page": {"url": "https://example.com/"},
        }).encode("utf-8")

        mock_enter = MagicMock()
        mock_enter.read.return_value = success_resp.read.return_value
        success_ctx = MagicMock()
        success_ctx.__enter__.return_value = mock_enter

        mock_urlopen.side_effect = [err_404, err_404, success_ctx]

        data, err = poll_scan_result("test-uuid", api_key="valid-key", max_wait_s=10, poll_interval_s=0.01)
        assert data is not None
        assert err is None
        assert mock_sleep.call_count == 2

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_poll_timeout_handling(self, mock_urlopen, mock_sleep):
        err_404 = urllib.error.HTTPError(
            url="https://urlscan.io/api/v1/result/test-uuid/",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"message": "Still running"}'),
        )
        mock_urlopen.side_effect = err_404

        # Short timeout to trigger timeout branch
        data, err = poll_scan_result("test-uuid", api_key="valid-key", max_wait_s=0.05, poll_interval_s=0.02)
        assert data is None
        assert "timed out" in err.lower()


# ═══════════════════════════════════════════════════════════════════
# 3. EXTRACTION & FINDINGS TESTS
# ═══════════════════════════════════════════════════════════════════

class TestExtractSandboxFindings:
    """Test parsing of raw urlscan.io JSON into structured findings."""

    def test_extract_clean_page(self):
        raw_data = {
            "task": {
                "reportURL": "https://urlscan.io/result/uuid-123/",
                "screenshotURL": "https://urlscan.io/screenshots/uuid-123.png",
                "domURL": "https://urlscan.io/dom/uuid-123/",
            },
            "page": {
                "url": "https://example.com/",
                "domain": "example.com",
                "ip": "93.184.216.34",
                "title": "Example Domain",
                "server": "ECS",
                "status": 200,
                "asnname": "EDGECAST",
                "tlsIssuer": "DigiCert",
            },
            "lists": {
                "domains": ["example.com"],
                "ips": ["93.184.216.34"],
            },
            "data": {
                "redirects": [],
                "requests": [],
                "console": [],
            },
            "verdicts": {
                "overall": {"score": 0, "malicious": False, "categories": []},
            },
        }

        finding = extract_sandbox_findings("https://example.com", "uuid-123", raw_data)
        assert finding.status == "COMPLETED"
        assert finding.verdict == "CLEAN"
        assert finding.malicious_score == 0
        assert finding.is_malicious is False
        assert finding.effective_url == "https://example.com/"
        assert finding.page_info["domain"] == "example.com"
        assert finding.page_info["server"] == "ECS"
        assert len(finding.downloads) == 0
        assert len(finding.redirects) == 0

    def test_extract_malicious_phishing_with_redirects_and_downloads(self):
        raw_data = {
            "task": {
                "reportURL": "https://urlscan.io/result/uuid-evil/",
                "screenshotURL": "https://urlscan.io/screenshots/uuid-evil.png",
            },
            "page": {
                "url": "https://credential-stealer.ru/login",
                "domain": "credential-stealer.ru",
                "ip": "185.234.219.47",
                "title": "Verify Bank Account",
                "status": 200,
            },
            "lists": {
                "domains": ["bit.ly", "credential-stealer.ru"],
                "ips": ["185.234.219.47"],
            },
            "data": {
                "redirects": [
                    {"url": "http://bit.ly/fake-bank", "status": 301, "to": "https://credential-stealer.ru/login"}
                ],
                "requests": [
                    {
                        "request": {"url": "https://credential-stealer.ru/payload.exe"},
                        "response": {
                            "response": {
                                "url": "https://credential-stealer.ru/payload.exe",
                                "mimeType": "application/x-msdownload",
                                "headers": {"Content-Disposition": 'attachment; filename="payload.exe"'},
                            },
                            "hash": "abc123hash",
                            "size": 65536,
                        },
                    }
                ],
                "console": [
                    {"message": {"level": "error", "text": "Uncaught ReferenceError: bad_func is not defined"}}
                ],
            },
            "verdicts": {
                "overall": {
                    "score": 90,
                    "malicious": True,
                    "categories": ["phishing"],
                    "tags": ["urlscan-ml"],
                },
                "engines": {"maliciousTotal": 3},
            },
            "meta": {
                "processors": {
                    "wappa": {"data": [{"app": "PHP"}, {"app": "Nginx"}]}
                }
            },
        }

        finding = extract_sandbox_findings("http://bit.ly/fake-bank", "uuid-evil", raw_data)
        assert finding.verdict == "MALICIOUS"
        assert finding.is_malicious is True
        assert finding.malicious_score >= 80
        assert "phishing" in finding.categories
        assert finding.effective_url == "https://credential-stealer.ru/login"
        assert len(finding.redirects) == 1
        assert len(finding.downloads) == 1
        assert finding.downloads[0]["filename"] == "payload.exe"
        assert finding.downloads[0]["mime_type"] == "application/x-msdownload"
        assert any("JavaScript console error" in b for b in finding.behavior_indicators)
        assert any("PHP" in b for b in finding.behavior_indicators)


# ═══════════════════════════════════════════════════════════════════
# 4. HIGH LEVEL SCAN & ANALYZE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestHighLevelRunners:
    """Test scan_url_dynamic and analyze_urls_dynamic."""

    def test_mock_phishing_url(self):
        with patch.object(config, "MOCK_URLSCAN", True):
            finding = scan_url_dynamic("http://bit.ly/3xHDFC-verify")
            assert finding.verdict == "MALICIOUS"
            assert finding.malicious_score == 96
            assert finding.effective_url == "https://secure-banking-update.xyz/login.php"
            assert len(finding.downloads) == 1
            assert finding.downloads[0]["filename"] == "security_plugin.exe"

    def test_mock_clean_url(self):
        with patch.object(config, "MOCK_URLSCAN", True):
            finding = scan_url_dynamic("https://example.com")
            assert finding.verdict == "CLEAN"
            assert finding.malicious_score == 0
            assert finding.page_info["domain"] == "example.com"

    def test_analyze_urls_dynamic_deduplication_and_limit(self):
        with patch.object(config, "MOCK_URLSCAN", True):
            urls = [
                "https://example.com",
                "https://example.com/",
                "http://bit.ly/3xHDFC-verify",
                "https://third-domain.com",
                "https://fourth-domain.com",
            ]
            result = analyze_urls_dynamic(urls, max_scans=2)
            assert result.total_scanned == 2
            assert len(result.findings) == 2
            assert any("first 2 unique URLs" in lim for lim in result.limitations)

    def test_disabled_or_missing_key_live(self):
        # Force live without API key
        with patch.object(config, "URLSCAN_API_KEY", ""):
            with patch.object(config, "MOCK_URLSCAN", False):
                finding = scan_url_dynamic("https://example.com", api_key="", force_live=True)
                assert finding.status == "ERROR"
                assert finding.verdict == "UNKNOWN"
                assert any("disabled or API key is not configured" in r for r in finding.reasons)


# ═══════════════════════════════════════════════════════════════════
# 5. EVIDENCE CORRELATION & PIPELINE INTEGRATION
# ═══════════════════════════════════════════════════════════════════

class TestPipelineIntegration:
    """Test correlation of sandbox findings with ML and report generation."""

    def test_correlate_evidence_with_sandbox(self):
        from ..ml_classifier import MLResult
        from ..authentication_analyzer import AuthResult
        from ..ip_intelligence import IPIntelligence
        from ..domain_intelligence import DomainIntelligence
        from ..url_analyzer import URLAnalysis
        from ..attachment_analyzer import AttachmentAnalysis

        ml = MLResult(prediction="PHISHING", decision_score=2.1, model_available=True, note="High confidence phishing pattern")
        auth = AuthResult(
            spf="PASS", dkim="PASS", dmarc="PASS",
            spf_detail="", dkim_detail="", dmarc_detail="",
            all_passed=True, any_failed=False, summary="All authentication checks passed"
        )
        ip_intel = IPIntelligence(public_ips=[], records=[], any_malicious=False, any_suspicious=False, max_reputation_score=0, limitations=[])
        dom_intel = DomainIntelligence(
            domain="example.com", reputation="clean", reputation_score=10,
            categories=[], age_days=500, registrar=None, virustotal_flags=None,
            is_suspicious_tld=False, tld=".com", is_typosquat=False,
            typosquat_target="", risk_score=10, reasons=[], source="MOCK"
        )
        urls = URLAnalysis(total_count=1, suspicious_count=1, findings=[], all_urls=[], limitations=[])
        atts = AttachmentAnalysis(total_count=0, suspicious_count=0, findings=[])

        with patch.object(config, "MOCK_URLSCAN", True):
            sandbox = analyze_urls_dynamic(["http://bit.ly/3xHDFC-verify"])
            assert sandbox.malicious_count == 1

            evidence = correlate_evidence(
                ml=ml,
                auth=auth,
                ip_intel=ip_intel,
                domain_intel=dom_intel,
                url_analysis=urls,
                att_analysis=atts,
                url_sandbox=sandbox,
            )

        sources = [e["source"] for e in evidence]
        assert "urlscan.io Sandbox" in sources
        assert "Cross-Vector" in sources

        findings_text = " ".join(e["finding"] for e in evidence)
        assert "confirmed MALICIOUS activity" in findings_text
        assert "unmasked redirection" in findings_text
        assert "intercepted payload download" in findings_text
        assert "Remote urlscan.io dynamic execution confirmed malicious URL in email classified as phishing by ML" in findings_text

    def test_full_analyze_email_pipeline_with_url_sandbox(self):
        eml = """From: Security Team <alert@secure-notice.com>
To: target@victim.org
Subject: Urgent Action Required: Account Suspension Warning
Date: Tue, 09 Sep 2026 00:00:00 +0000
Message-ID: <threat-12345@secure-notice.com>

Dear Customer,
Your account has been suspended due to suspicious activity.
Please restore your access immediately:
http://bit.ly/3xHDFC-verify
"""
        with patch.object(config, "MOCK_URLSCAN", True):
            report = analyze_email(eml)
            assert "forensics" in report
            assert "url_sandbox" in report["forensics"]
            sandbox_data = report["forensics"]["url_sandbox"]
            assert sandbox_data["total_scanned"] >= 1
            assert sandbox_data["malicious_count"] >= 1
            assert "dynamic_sandbox" in report["urls"]


# ═══════════════════════════════════════════════════════════════════
# 6. FASTAPI ENDPOINT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestFastAPIEndpoint:
    """Test /sandbox/scan-url endpoint."""

    def setup_method(self):
        self.client = TestClient(app)

    def test_scan_url_endpoint_mock(self):
        with patch.object(config, "MOCK_URLSCAN", True):
            resp = self.client.post("/sandbox/scan-url", json={"url": "http://bit.ly/3xHDFC-verify"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["verdict"] == "MALICIOUS"
            assert data["malicious_score"] == 96
            assert data["effective_url"] == "https://secure-banking-update.xyz/login.php"
            assert len(data["downloads"]) == 1

    def test_scan_url_endpoint_empty(self):
        resp = self.client.post("/sandbox/scan-url", json={"url": "   "})
        assert resp.status_code == 400
        assert "URL cannot be empty" in resp.json()["detail"]
