"""
GmailGuard — PhishTank Integration Tests

Tests:
1. URL found and verified
2. URL not found
3. API unavailable
4. API timeout/error
5. Missing API key
6. Multiple URLs
7. Duplicate URLs not queried twice
8. Pipeline integration
"""

import json
import urllib.error
from unittest.mock import patch, MagicMock
import pytest

from .. import config
from ..phish_tank import (
    MockPhishTankProvider,
    LivePhishTankProvider,
    UnavailablePhishTankProvider,
    get_phishtank_provider,
    check_urls_phishtank,
    PhishTankResult,
    PhishTankAnalysis,
)


class TestMockPhishTankProvider:
    """Test the deterministic mock PhishTank provider."""

    def setup_method(self):
        self.provider = MockPhishTankProvider()

    def test_known_phishing_url_found_and_verified(self):
        result = self.provider.check_url("http://bit.ly/3xHDFC-verify")
        assert result.in_database is True
        assert result.verified is True
        assert result.valid is True
        assert result.phish_id == "8901234"
        assert result.source == "Mock/Demo"
        assert result.error is None

    def test_url_not_found(self):
        result = self.provider.check_url("https://google.com")
        assert result.in_database is False
        assert result.verified is False
        assert result.valid is False
        assert result.phish_id is None
        assert result.source == "Mock/Demo"

    def test_not_found_does_not_mean_safe(self):
        """A URL not in PhishTank should NOT be treated as safe."""
        result = self.provider.check_url("https://unknown-phish.example.com")
        assert result.in_database is False
        # No 'safe' or 'clean' field — absence of data is not evidence of safety

    def test_result_to_dict_serializable(self):
        result = self.provider.check_url("http://bit.ly/3xHDFC-verify")
        d = result.to_dict()
        assert d["url"] == "http://bit.ly/3xHDFC-verify"
        assert d["in_database"] is True
        assert d["verified"] is True
        assert d["phish_id"] == "8901234"
        assert d["source"] == "Mock/Demo"
        # Must be JSON serializable
        json.dumps(d)


class TestLivePhishTankProvider:
    """Test the live PhishTank provider with mocked HTTP."""

    def setup_method(self):
        self.provider = LivePhishTankProvider(api_key="fake-test-key")

    @patch("urllib.request.urlopen")
    def test_url_found_in_phishtank(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "results": {
                "in_database": True,
                "verified": True,
                "valid": True,
                "phish_id": "9999999",
            }
        }).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = self.provider.check_url("http://evil.example.com/login")
        assert result.in_database is True
        assert result.verified is True
        assert result.phish_id == "9999999"
        assert result.source == "PhishTank"

    @patch("urllib.request.urlopen")
    def test_url_not_in_phishtank(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "results": {"in_database": False}
        }).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = self.provider.check_url("https://safe.example.com")
        assert result.in_database is False
        assert result.verified is False
        assert result.source == "PhishTank"

    @patch("urllib.request.urlopen")
    def test_api_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://checkurl.phishtank.com/checkurl/",
            code=509,
            msg="Bandwidth Limit Exceeded",
            hdrs={},
            fp=MagicMock(),
        )
        result = self.provider.check_url("http://example.com")
        assert result.in_database is False
        assert result.error is not None
        assert "509" in result.error

    @patch("urllib.request.urlopen")
    def test_api_timeout(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("Connection timed out")
        result = self.provider.check_url("http://example.com")
        assert result.in_database is False
        assert result.error is not None
        assert "TimeoutError" in result.error


class TestUnavailableProvider:
    """Test fallback when API key is not configured."""

    def test_missing_api_key_returns_unavailable(self):
        provider = UnavailablePhishTankProvider()
        result = provider.check_url("http://example.com")
        assert result.source == "Unavailable"
        assert result.in_database is False
        assert result.error is not None
        assert "not configured" in result.error.lower()


class TestProviderFactory:
    """Test get_phishtank_provider() factory."""

    def test_mock_mode_returns_mock_provider(self):
        with patch.object(config, "MOCK_PHISHTANK", True):
            provider = get_phishtank_provider()
            assert isinstance(provider, MockPhishTankProvider)

    def test_live_key_returns_live_provider(self):
        with patch.object(config, "MOCK_PHISHTANK", False), \
             patch.object(config, "PHISHTANK_API_KEY", "real-key"):
            provider = get_phishtank_provider()
            assert isinstance(provider, LivePhishTankProvider)

    def test_no_key_no_mock_returns_unavailable(self):
        with patch.object(config, "MOCK_PHISHTANK", False), \
             patch.object(config, "PHISHTANK_API_KEY", ""):
            provider = get_phishtank_provider()
            assert isinstance(provider, UnavailablePhishTankProvider)


class TestCheckUrlsPhishtank:
    """Test the orchestrator function."""

    def test_multiple_urls(self):
        urls = [
            "http://bit.ly/3xHDFC-verify",
            "https://google.com",
            "http://hdfcbank-secure.co.in/login.php",
        ]
        analysis = check_urls_phishtank(urls, provider=MockPhishTankProvider())
        assert len(analysis.results) == 3
        assert analysis.verified_phishing_count == 2
        assert analysis.source == "Mock/Demo"

    def test_duplicate_urls_queried_once(self):
        urls = [
            "http://bit.ly/3xHDFC-verify",
            "http://bit.ly/3xHDFC-verify",
            "http://bit.ly/3xHDFC-verify",
        ]
        analysis = check_urls_phishtank(urls, provider=MockPhishTankProvider())
        assert len(analysis.results) == 1  # Only one lookup

    def test_empty_url_list(self):
        analysis = check_urls_phishtank([], provider=MockPhishTankProvider())
        assert len(analysis.results) == 0
        assert analysis.verified_phishing_count == 0

    def test_analysis_to_dict_serializable(self):
        urls = ["http://bit.ly/3xHDFC-verify", "https://google.com"]
        analysis = check_urls_phishtank(urls, provider=MockPhishTankProvider())
        d = analysis.to_dict()
        json.dumps(d)  # Must not raise
        assert d["verified_phishing_count"] == 1
        assert d["source"] == "Mock/Demo"


class TestPipelineIntegration:
    """Test PhishTank integration in the full pipeline."""

    def test_phishing_email_has_phishtank_results(self):
        from pathlib import Path
        sample = Path("sample_emails/phishing_bank.eml")
        if not sample.exists():
            pytest.skip("Sample email file not found")

        from ..main import analyze_email
        raw = sample.read_text(encoding="utf-8", errors="replace")
        report = analyze_email(raw)

        # PhishTank results should be in forensics
        assert "phishtank" in report["forensics"]
        pt = report["forensics"]["phishtank"]
        assert pt["source"] == "Mock/Demo"
        assert pt["verified_phishing_count"] >= 1

        # Should appear in correlated evidence
        corr = report.get("correlated_evidence", [])
        phishtank_findings = [c for c in corr if c["source"] == "PhishTank"]
        assert len(phishtank_findings) >= 1

    def test_legitimate_email_no_phishtank_hits(self):
        from pathlib import Path
        sample = Path("sample_emails/legitimate.eml")
        if not sample.exists():
            pytest.skip("Sample email file not found")

        from ..main import analyze_email
        raw = sample.read_text(encoding="utf-8", errors="replace")
        report = analyze_email(raw)

        assert "phishtank" in report["forensics"]
        pt = report["forensics"]["phishtank"]
        assert pt["verified_phishing_count"] == 0
