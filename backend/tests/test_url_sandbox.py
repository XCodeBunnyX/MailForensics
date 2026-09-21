"""
GmailGuard — Local Browserless Chromium Sandbox Tests

Tests:
1. SSRF Protection: localhost, 127.0.0.1, IPv6 loopback (::1), RFC 1918 private IPs,
   link-local (169.254.169.254), invalid schemes, empty URL.
2. Live Browserless Execution: https://example.com, screenshot file creation,
   status=COMPLETED, title extraction, network event capture, contacted domains/IPs.
3. Redirect handling & chain capture.
4. Console & Page Error capturing.
5. Download detection without host execution.
6. Timeout handling & graceful degradation.
7. Cleanup on error: isolated context & browser closed.
8. Deterministic mock mode fallback (MOCK_URLSCAN=True).
9. Batch analysis (analyze_urls_dynamic): deduplication & rate limits.
10. FastAPI endpoints: POST /sandbox/scan-url and GET /screenshots/{filename}.png.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from .. import config
from ..api import app
from ..url_sandbox import (
    URLScanFinding,
    URLSandboxAnalysis,
    analyze_urls_dynamic,
    is_ssrf_risk,
    scan_url_browserless,
    scan_url_dynamic,
)


# ═══════════════════════════════════════════════════════════════════
# 1. SSRF PROTECTION TESTS
# ═══════════════════════════════════════════════════════════════════

class TestSSRFProtection:
    """Validate that local, private, and internal IPs are strictly blocked."""

    def test_localhost_blocked(self):
        blocked, reason = is_ssrf_risk("http://localhost:3000")
        assert blocked is True
        assert "blocked" in reason.lower()

    def test_127_loopback_blocked(self):
        blocked, reason = is_ssrf_risk("http://127.0.0.1/admin")
        assert blocked is True
        assert "loopback" in reason.lower() or "blocked" in reason.lower()

    def test_127_subnet_blocked(self):
        blocked, reason = is_ssrf_risk("http://127.0.0.2:8080")
        assert blocked is True
        assert "blocked" in reason.lower()

    def test_ipv6_loopback_blocked(self):
        blocked, reason = is_ssrf_risk("http://[::1]:8000")
        assert blocked is True
        assert "loopback" in reason.lower() or "blocked" in reason.lower()

    def test_rfc1918_10_network_blocked(self):
        blocked, reason = is_ssrf_risk("http://10.0.0.5/internal")
        assert blocked is True
        assert "private" in reason.lower() or "blocked" in reason.lower()

    def test_rfc1918_192_168_network_blocked(self):
        blocked, reason = is_ssrf_risk("http://192.168.1.1/router")
        assert blocked is True
        assert "private" in reason.lower() or "blocked" in reason.lower()

    def test_rfc1918_172_16_network_blocked(self):
        blocked, reason = is_ssrf_risk("http://172.16.0.1:8080")
        assert blocked is True
        assert "private" in reason.lower() or "blocked" in reason.lower()

    def test_link_local_cloud_metadata_blocked(self):
        blocked, reason = is_ssrf_risk("http://169.254.169.254/latest/meta-data")
        assert blocked is True
        assert "blocked" in reason.lower()

    def test_unsupported_scheme_blocked(self):
        blocked, reason = is_ssrf_risk("ftp://example.com/file.txt")
        assert blocked is True
        assert "scheme" in reason.lower()

    def test_public_domain_allowed(self):
        blocked, reason = is_ssrf_risk("https://example.com")
        assert blocked is False
        assert reason == ""

    def test_scan_url_dynamic_ssrf_returns_blocked_status(self):
        finding = scan_url_dynamic("http://localhost:3000", force_live=True)
        assert finding.status == "BLOCKED"
        assert finding.verdict == "UNKNOWN"
        assert finding.intelligence_available is True
        assert "SSRF_ATTEMPT_BLOCKED" in finding.behavior_indicators
        assert any("SSRF" in r for r in finding.reasons)


# ═══════════════════════════════════════════════════════════════════
# 2. LIVE BROWSERLESS EXECUTION TESTS (https://example.com)
# ═══════════════════════════════════════════════════════════════════

class TestLiveBrowserlessSandbox:
    """Test live dynamic browser execution against self-hosted Browserless container."""

    def test_successful_scan_example_com(self):
        finding = scan_url_dynamic("https://example.com", force_live=True)

        assert finding.status == "COMPLETED"
        assert finding.verdict in ("CLEAN", "UNKNOWN")
        assert finding.is_malicious is False
        assert finding.effective_url.startswith("https://example.com")
        assert "example.com" in finding.contacted_domains
        assert finding.page_info.get("title") == "Example Domain"
        assert finding.page_info.get("status_code") == 200

        # Verify screenshot creation
        assert finding.screenshot_url.startswith("/screenshots/")
        filename = finding.screenshot_url.replace("/screenshots/", "")
        screenshot_path = Path(config.SCREENSHOTS_DIR) / filename
        assert screenshot_path.exists(), f"Screenshot file not found: {screenshot_path}"
        assert screenshot_path.stat().st_size > 1000, "Screenshot file is too small or empty"

    def test_contacted_ips_and_network_telemetry(self):
        finding = scan_url_dynamic("https://example.com", force_live=True)
        assert finding.status == "COMPLETED"
        assert len(finding.network_requests) >= 1
        assert finding.network_requests[0]["method"] in ("GET", "POST")


# ═══════════════════════════════════════════════════════════════════
# 3. BEHAVIORAL TELEMETRY & ERROR CAPTURE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestBehavioralTelemetry:
    """Test capture of redirects, console errors, page errors, and downloads."""

    def test_redirect_detection(self):
        # http://example.com redirects to https://example.com/
        finding = scan_url_dynamic("http://example.com", force_live=True)
        assert finding.status == "COMPLETED"
        assert finding.effective_url.startswith("https://")
        assert "REDIRECT" in finding.behavior_indicators or len(finding.redirects) > 0

    @patch("playwright.sync_api.sync_playwright")
    def test_console_and_page_errors_captured(self, mock_playwright):
        # Mock Playwright to emit console error and page error
        mock_p = MagicMock()
        mock_browser = MagicMock()
        mock_ctx = MagicMock()
        mock_page = MagicMock()

        mock_playwright.return_value.__enter__.return_value = mock_p
        mock_p.chromium.connect.return_value = mock_browser
        mock_browser.new_context.return_value = mock_ctx
        mock_ctx.new_page.return_value = mock_page

        def fake_goto(url, **kwargs):
            # Trigger listeners
            listeners = mock_page.on.call_args_list
            for call in listeners:
                event_name, handler = call[0][0], call[0][1]
                if event_name == "console":
                    msg = MagicMock()
                    msg.type = "error"
                    msg.text = "Uncaught SyntaxError: Unexpected token"
                    handler(msg)
                elif event_name == "pageerror":
                    handler(Exception("DOM Exception: quota exceeded"))
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = {"server": "TestServer"}
            mock_resp.request.redirected_from = None
            return mock_resp

        mock_page.goto.side_effect = fake_goto
        mock_page.url = "https://safe-test.org/"
        mock_page.title.return_value = "Test Site"

        finding = scan_url_browserless("https://safe-test.org")
        assert finding.status == "COMPLETED"
        assert "CONSOLE_ERROR" in finding.behavior_indicators
        assert "PAGE_ERROR" in finding.behavior_indicators
        assert any("Unexpected token" in err for err in finding.console_errors)
        assert any("quota exceeded" in err for err in finding.page_errors)

    @patch("playwright.sync_api.sync_playwright")
    def test_download_detection_and_quarantine(self, mock_playwright):
        # Mock download event
        mock_p = MagicMock()
        mock_browser = MagicMock()
        mock_ctx = MagicMock()
        mock_page = MagicMock()

        mock_playwright.return_value.__enter__.return_value = mock_p
        mock_p.chromium.connect.return_value = mock_browser
        mock_browser.new_context.return_value = mock_ctx
        mock_ctx.new_page.return_value = mock_page

        mock_download = MagicMock()
        mock_download.suggested_filename = "malicious_invoice.exe"
        mock_download.url = "https://evil-host.com/dl/malicious_invoice.exe"

        def fake_goto(url, **kwargs):
            for call in mock_page.on.call_args_list:
                event_name, handler = call[0][0], call[0][1]
                if event_name == "download":
                    handler(mock_download)
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = {}
            mock_resp.request.redirected_from = None
            return mock_resp

        mock_page.goto.side_effect = fake_goto
        mock_page.url = "https://evil-host.com/download"
        mock_page.title.return_value = "Download Portal"

        finding = scan_url_browserless("https://evil-host.com/download")
        assert finding.status == "COMPLETED"
        assert finding.verdict == "MALICIOUS"
        assert finding.is_malicious is True
        assert finding.malicious_score >= 80
        assert "DOWNLOAD_DETECTED" in finding.behavior_indicators
        assert len(finding.downloads) == 1
        assert finding.downloads[0]["filename"] == "malicious_invoice.exe"
        # Verify download was cancelled / discarded
        mock_download.cancel.assert_called_once()


# ═══════════════════════════════════════════════════════════════════
# 4. TIMEOUT & CLEANUP TESTS
# ═══════════════════════════════════════════════════════════════════

class TestTimeoutAndCleanup:
    """Test timeout handling and resource cleanup."""

    @patch("playwright.sync_api.sync_playwright")
    def test_timeout_handling(self, mock_playwright):
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        mock_p = MagicMock()
        mock_browser = MagicMock()
        mock_ctx = MagicMock()
        mock_page = MagicMock()

        mock_playwright.return_value.__enter__.return_value = mock_p
        mock_p.chromium.connect.return_value = mock_browser
        mock_browser.new_context.return_value = mock_ctx
        mock_ctx.new_page.return_value = mock_page

        # Simulate timeout on page.goto
        mock_page.goto.side_effect = PlaywrightTimeoutError("Navigation timeout of 30000ms exceeded")
        mock_page.url = "https://very-slow-site.com"
        mock_page.title.return_value = "Slow Site"

        finding = scan_url_browserless("https://very-slow-site.com")
        assert finding.status == "TIMEOUT"
        assert finding.verdict == "UNKNOWN"
        # Context and browser closed
        mock_ctx.close.assert_called()
        mock_browser.close.assert_called()


    @patch("playwright.sync_api.sync_playwright")
    def test_cleanup_after_connection_failure(self, mock_playwright):
        mock_p = MagicMock()
        mock_playwright.return_value.__enter__.return_value = mock_p
        mock_p.chromium.connect.side_effect = ConnectionRefusedError("Docker container unreachable")

        finding = scan_url_browserless("https://example.com")
        assert finding.status == "FAILED"
        assert finding.verdict == "UNKNOWN"
        assert finding.intelligence_available is False
        assert "unreachable" in (finding.error or "")


# ═══════════════════════════════════════════════════════════════════
# 5. MOCK MODE TESTS (MOCK_URLSCAN=True)
# ═══════════════════════════════════════════════════════════════════

class TestMockMode:
    """Validate deterministic mock responses for testing and offline development."""

    def test_mock_phishing_url(self):
        with patch.object(config, "MOCK_URLSCAN", True):
            finding = scan_url_dynamic("http://bit.ly/3xHDFC-verify")
            assert finding.mode == "MOCK"
            assert finding.verdict == "MALICIOUS"
            assert finding.malicious_score == 96
            assert finding.effective_url == "https://secure-banking-update.xyz/login.php"
            assert len(finding.downloads) == 1
            assert finding.downloads[0]["filename"] == "security_plugin.exe"

    def test_mock_clean_url(self):
        with patch.object(config, "MOCK_URLSCAN", True):
            finding = scan_url_dynamic("https://example.com")
            assert finding.mode == "MOCK"
            assert finding.verdict == "CLEAN"
            assert finding.malicious_score == 0
            assert finding.page_info["domain"] == "example.com"

    def test_mock_unknown_url_returns_unknown_verdict(self):
        with patch.object(config, "MOCK_URLSCAN", True):
            finding = scan_url_dynamic("https://arbitrary-unseen-target.org/path")
            assert finding.mode == "MOCK"
            assert finding.verdict == "UNKNOWN"
            assert finding.intelligence_available is False


# ═══════════════════════════════════════════════════════════════════
# 6. BATCH RUNNER & DEDUPLICATION TESTS
# ═══════════════════════════════════════════════════════════════════

class TestBatchRunner:
    """Test analyze_urls_dynamic deduplication and scan limiting."""

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


# ═══════════════════════════════════════════════════════════════════
# 7. FASTAPI REST ENDPOINT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestFastAPIEndpoints:
    """Test /sandbox/scan-url and /screenshots static serving."""

    def setup_method(self):
        self.client = TestClient(app)

    def test_scan_url_endpoint_success(self):
        resp = self.client.post("/sandbox/scan-url", json={"url": "https://example.com", "force_live": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "COMPLETED"
        assert data["effective_url"].startswith("https://example.com")
        assert data["screenshot_url"].startswith("/screenshots/")

        # Test static screenshot retrieval
        ss_resp = self.client.get(data["screenshot_url"])
        assert ss_resp.status_code == 200
        assert ss_resp.headers["content-type"].startswith("image/png")

    def test_scan_url_endpoint_ssrf_blocked(self):
        resp = self.client.post("/sandbox/scan-url", json={"url": "http://127.0.0.1:3000", "force_live": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "BLOCKED"
        assert "SSRF_ATTEMPT_BLOCKED" in data["behavior_indicators"]

    def test_scan_url_endpoint_empty_url_returns_400(self):
        resp = self.client.post("/sandbox/scan-url", json={"url": "   "})
        assert resp.status_code == 400
        assert "URL cannot be empty" in resp.json()["detail"]
