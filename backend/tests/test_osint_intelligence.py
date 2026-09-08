"""
GmailGuard — OSINT Intelligence Tests

Validates:
- Domain OSINT lookup
- IP OSINT lookup
- URL OSINT lookup
- Provider abstraction & switching
- Mock provider deterministic outputs & labels
- Missing API key / Unavailable provider fallback
- Provider failure & error handling (mocked HTTP errors, timeouts)
- Missing historical data handling
- Deduplication of indicators (domains, IPs, URLs)
- Evidence correlation (cross-signal synthesis)
- Integration with the complete pipeline
"""

import json
import urllib.error
from unittest.mock import patch, MagicMock
import pytest

from .. import config
from ..ioc_extractor import extract_iocs, IOCBundle
from ..osint_intelligence import (
    MockOSINTProvider,
    VirusTotalOSINTProvider,
    UnavailableOSINTProvider,
    get_osint_provider,
    run_osint_analysis,
    NormalizedOSINTRecord,
)
from ..evidence_correlator import correlate_evidence
from ..email_parser import parse_email
from ..main import analyze_email


# ═══════════════════════════════════════════════════════════════════
# 1. PROVIDER ABSTRACTION & MOCK PROVIDER
# ═══════════════════════════════════════════════════════════════════

class TestMockOSINTProvider:
    """Test the deterministic mock OSINT provider."""

    def setup_method(self):
        self.provider = MockOSINTProvider()

    def test_provider_name_is_mock_demo(self):
        assert self.provider.name() == "Mock/Demo"

    def test_domain_osint_lookup(self):
        rec = self.provider.investigate_domain("hdfcbank-secure.co.in")
        assert isinstance(rec, NormalizedOSINTRecord)
        assert rec.indicator == "hdfcbank-secure.co.in"
        assert rec.indicator_type == "domain"
        assert rec.data_source == "Mock/Demo"
        assert "dns" in rec.current_information
        assert "185.234.219.47" in rec.current_information["dns"]["A"]
        assert len(rec.historical_information["ips"]) >= 1
        assert len(rec.security_observations) >= 1
        assert len(rec.timeline) >= 1

    def test_sender_domain_osint_lookup_flag(self):
        rec = self.provider.investigate_domain("hdfcbank-secure.co.in", is_sender=True)
        assert rec.indicator_type == "sender_domain"

    def test_ip_osint_lookup(self):
        rec = self.provider.investigate_ip("185.234.219.47")
        assert rec.indicator == "185.234.219.47"
        assert rec.indicator_type == "ip"
        assert rec.data_source == "Mock/Demo"
        assert rec.current_information["asn"] == "AS64496"
        assert "Bulletproof" in rec.current_information["isp"]
        assert len(rec.security_observations) >= 1
        assert len(rec.related_infrastructure) >= 1

    def test_url_osint_lookup(self):
        rec = self.provider.investigate_url("http://bit.ly/3xHDFC-verify")
        assert rec.indicator == "http://bit.ly/3xHDFC-verify"
        assert rec.indicator_type == "url"
        assert rec.data_source == "Mock/Demo"
        assert rec.current_information["reputation"] == "suspicious"
        assert "URL Shortener" in rec.current_information["categories"]
        assert len(rec.security_observations) >= 1

    def test_unlisted_ip_graceful_fallback(self):
        rec = self.provider.investigate_ip("198.51.100.254")
        assert rec.indicator == "198.51.100.254"
        assert rec.data_source == "Mock/Demo"
        assert len(rec.limitations) >= 1

    def test_unlisted_url_graceful_fallback(self):
        rec = self.provider.investigate_url("https://unlisted-domain.org/test")
        assert rec.data_source == "Mock/Demo"
        assert rec.current_information["detection_count"] == 0


# ═══════════════════════════════════════════════════════════════════
# 2. VIRUSTOTAL PROVIDER (MOCKED RESPONSES)
# ═══════════════════════════════════════════════════════════════════

class TestVirusTotalOSINTProvider:
    """Test VirusTotal provider with mocked HTTP responses."""

    def setup_method(self):
        self.provider = VirusTotalOSINTProvider(api_key="fake-test-key-12345")

    @patch("urllib.request.urlopen")
    def test_vt_domain_lookup_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60},
                    "last_dns_records": [
                        {"type": "A", "value": "1.2.3.4"},
                        {"type": "NS", "value": "ns1.example.com"},
                    ],
                    "creation_date": 1700000000,
                    "registrar": "Example Registrar",
                }
            }
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        rec = self.provider.investigate_domain("example.com")
        assert rec.data_source == "VirusTotal"
        assert rec.current_information["reputation"]["malicious_count"] == 5
        assert rec.current_information["dns"]["A"] == ["1.2.3.4"]
        assert len(rec.security_observations) >= 1
        assert len(rec.evidence) >= 1

    @patch("urllib.request.urlopen")
    def test_vt_ip_lookup_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "asn": 12345,
                    "as_owner": "Test Cloud Provider",
                    "country": "US",
                    "reverse_dns": "mail.test.com",
                    "last_analysis_stats": {"malicious": 3, "suspicious": 0},
                }
            }
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        rec = self.provider.investigate_ip("1.2.3.4")
        assert rec.data_source == "VirusTotal"
        assert rec.current_information["asn"] == "AS12345"
        assert rec.current_information["isp"] == "Test Cloud Provider"
        assert rec.current_information["reputation"] == "suspicious"
        assert len(rec.security_observations) >= 1

    @patch("urllib.request.urlopen")
    def test_vt_url_lookup_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 7, "harmless": 65},
                    "categories": {"VendorA": "phishing", "VendorB": "malicious"},
                }
            }
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        rec = self.provider.investigate_url("http://phish.com/login")
        assert rec.data_source == "VirusTotal"
        assert rec.current_information["detection_count"] == 7
        assert "phishing" in rec.current_information["categories"]

    @patch("urllib.request.urlopen")
    def test_vt_http_404_handling(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://virustotal.com/api",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=MagicMock(),
        )

        rec = self.provider.investigate_domain("unknown-domain.org")
        assert rec.data_source == "VirusTotal"
        assert any("404" in lim for lim in rec.limitations)

    @patch("urllib.request.urlopen")
    def test_vt_network_timeout_handling(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("Connection timed out")

        rec = self.provider.investigate_ip("5.6.7.8")
        assert rec.data_source == "VirusTotal"
        assert any("timed out" in lim.lower() or "error" in lim.lower() for lim in rec.limitations)


# ═══════════════════════════════════════════════════════════════════
# 3. UNAVAILABLE PROVIDER & FACTORY
# ═══════════════════════════════════════════════════════════════════

class TestUnavailableProvider:
    """Test fallback behavior when no API key is set and mock mode is off."""

    def test_unavailable_records(self):
        provider = UnavailableOSINTProvider()
        rec = provider.investigate_domain("example.com")
        assert rec.data_source == "Unavailable"
        assert "not configured" in rec.limitations[0]

        ip_rec = provider.investigate_ip("1.2.3.4")
        assert ip_rec.data_source == "Unavailable"

    def test_factory_returns_mock_when_mock_osint_true(self):
        with patch.object(config, "MOCK_OSINT", True):
            provider = get_osint_provider()
            assert isinstance(provider, MockOSINTProvider)

    def test_factory_returns_unavailable_when_no_key(self):
        with patch.object(config, "MOCK_OSINT", False), \
             patch.object(config, "VIRUSTOTAL_API_KEY", ""):
            provider = get_osint_provider()
            assert isinstance(provider, UnavailableOSINTProvider)

    def test_factory_returns_vt_when_key_present(self):
        with patch.object(config, "MOCK_OSINT", False), \
             patch.object(config, "VIRUSTOTAL_API_KEY", "real-api-key"):
            provider = get_osint_provider()
            assert isinstance(provider, VirusTotalOSINTProvider)


# ═══════════════════════════════════════════════════════════════════
# 4. IOC EXTRACTION & DEDUPLICATION
# ═══════════════════════════════════════════════════════════════════

class TestIOCExtraction:
    """Test extraction and deduplication of IOCs."""

    def test_deduplication_of_domain_across_multiple_urls(self):
        raw = (
            "From: alerts@hdfcbank-secure.co.in\r\n"
            "To: victim@example.com\r\n"
            "Subject: Verify\r\n\r\n"
            "Click here: https://hdfcbank-secure.co.in/login\r\n"
            "Or here: https://hdfcbank-secure.co.in/account\r\n"
            "Or here: http://hdfcbank-secure.co.in/reset\r\n"
        )
        parsed = parse_email(raw)
        from ..url_analyzer import analyze_urls
        urls = analyze_urls(parsed.text_body, parsed.html_body)

        bundle = extract_iocs(parsed, url_analysis=urls)
        # The domain should only appear once in domains
        assert bundle.domains.count("hdfcbank-secure.co.in") == 1
        assert "hdfcbank-secure.co.in" in bundle.domains

    def test_deduplication_of_duplicate_ips(self):
        raw = (
            "Received: from mail.example.com ([185.234.219.47])\r\n"
            "Received: from relay.example.com ([185.234.219.47])\r\n"
            "From: sender@domain.com\r\n"
            "Subject: Test\r\n\r\n"
            "Body"
        )
        parsed = parse_email(raw)
        from ..ip_intelligence import analyze_ips
        ip_intel = analyze_ips(parsed)

        bundle = extract_iocs(parsed, ip_intel=ip_intel)
        assert bundle.ips.count("185.234.219.47") == 1


# ═══════════════════════════════════════════════════════════════════
# 5. EVIDENCE CORRELATION
# ═══════════════════════════════════════════════════════════════════

class TestEvidenceCorrelation:
    """Test multi-signal cross-vector correlation."""

    def test_cross_vector_correlation_emitted(self):
        raw = (
            "Received: from bulletproof ([185.234.219.47])\r\n"
            "Authentication-Results: spf=fail; dkim=fail\r\n"
            "From: alert@hdfcbank-secure.co.in\r\n"
            "Subject: URGENT ACCOUNT SUSPENSION NOTICE\r\n\r\n"
            "Your account is suspended. Verify credentials: http://bit.ly/3xHDFC-verify\r\n"
        )
        report = analyze_email(raw)
        corr = report.get("correlated_evidence", [])
        assert len(corr) > 0

        # Check for presence of cross-vector findings
        sources = [c["source"] for c in corr]
        assert "ML" in sources
        assert "Authentication" in sources
        assert "Cross-Vector" in sources

    def test_clean_email_correlation(self):
        raw = (
            "Authentication-Results: spf=pass; dkim=pass\r\n"
            "From: boss@legitimate-company.com\r\n"
            "Subject: Team meeting on Thursday\r\n\r\n"
            "Hi everyone, see you at 10 AM.\r\n"
        )
        report = analyze_email(raw)
        corr = report.get("correlated_evidence", [])
        assert any(c["source"] == "Authentication" and "verified" in c["finding"].lower() for c in corr)


# ═══════════════════════════════════════════════════════════════════
# 6. FULL PIPELINE INTEGRATION
# ═══════════════════════════════════════════════════════════════════

class TestPipelineIntegration:
    """Test full pipeline execution with OSINT layer."""

    def test_phishing_sample_pipeline(self):
        from pathlib import Path
        sample = Path("sample_emails/phishing_bank.eml")
        if not sample.exists():
            pytest.skip("Sample email file not found")

        raw = sample.read_text(encoding="utf-8", errors="replace")
        report = analyze_email(raw)

        # Check report schema
        assert "forensics" in report
        forensics = report["forensics"]
        assert "osint" in forensics
        osint = forensics["osint"]

        assert "domains" in osint
        assert "ips" in osint
        assert "urls" in osint
        assert osint["data_source"] == "Mock/Demo"

        # Check top-level correlated evidence
        assert "correlated_evidence" in report
        assert isinstance(report["correlated_evidence"], list)
        assert len(report["correlated_evidence"]) >= 1

    def test_legitimate_sample_pipeline(self):
        from pathlib import Path
        sample = Path("sample_emails/legitimate.eml")
        if not sample.exists():
            pytest.skip("Sample email file not found")

        raw = sample.read_text(encoding="utf-8", errors="replace")
        report = analyze_email(raw)

        assert report["threat_score"] < 50
        assert "forensics" in report
        assert "osint" in report["forensics"]
