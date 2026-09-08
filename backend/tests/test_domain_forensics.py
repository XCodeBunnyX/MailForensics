"""
test_domain_forensics.py — Unit tests for forensic_domain_intelligence.py

Tests:
  1.  Domain extraction from parsed email + URL analysis
  2.  Current DNS parsing / normalization
  3.  Historical DNS normalization
  4.  Historical IP normalization
  5.  WHOIS history normalization
  6.  Security detection parsing
  7.  Timeline generation
  8.  Chronological sorting
  9.  Duplicate domain handling (per-request cache)
  10. Missing provider data (domain not in mock DB)
  11. API unavailable (_UnavailableProvider)
  12. Mock provider correctness
  13. No fabricated data (unknown domain → empty, not fake)
  14. End-to-end integration with analyze_email

Tests must not require live external APIs.
All external API responses are mocked at the provider level.
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import patch, MagicMock

from .. import forensic_domain_intelligence
from ..forensic_domain_intelligence import (
    MockDomainIntelligenceProvider,
    _UnavailableProvider,
    _normalize,
    _collect_domains,
    _build_timeline_and_evidence,
    run_forensic_domain_analysis,
    get_forensic_domain_intel,
    get_current_dns,
    get_historical_ips,
    get_security_detections,
    build_domain_timeline,
    DomainForensicResult,
    ForensicIntelligenceResult,
    DNSRecordSet,
    HistoricalIP,
    HistoricalDNSRecord,
    WhoisRecord,
    SecurityHistory,
    TimelineEvent,
    ForensicEvidence,
)


# ── Helpers ───────────────────────────────────────────────────────

def _make_parsed(sender_domain: str = "example.com") -> MagicMock:
    m = MagicMock()
    m.sender_domain = sender_domain
    return m


def _make_url_analysis(domains: list[str]) -> MagicMock:
    findings = []
    for d in domains:
        f = MagicMock()
        f.domain = d
        findings.append(f)
    m = MagicMock()
    m.findings = findings
    return m


def _minimal_raw(
    a_records: list[str] = None,
    hist_ips: list[dict] = None,
    whois: list[dict] = None,
    detections: list[dict] = None,
    prev_detected: bool = False,
    curr_detected: bool = False,
    hist_a: list[dict] = None,
) -> dict:
    return {
        "current_dns": {
            "A": a_records or [], "AAAA": [], "MX": [], "NS": [], "CNAME": [], "TXT": [],
        },
        "historical_dns": {
            "A":     hist_a or [],
            "AAAA":  [], "MX": [], "NS": [], "CNAME": [],
        },
        "historical_ips": hist_ips or [],
        "whois_history":  whois or [],
        "security_history": {
            "previously_detected": prev_detected,
            "currently_detected":  curr_detected,
            "detections": detections or [],
        },
    }


# ═══════════════════════════════════════════════════════════════════
# 1. Domain Extraction
# ═══════════════════════════════════════════════════════════════════
class TestDomainExtraction:
    def test_sender_domain_included(self):
        parsed = _make_parsed("example.com")
        url_a  = _make_url_analysis([])
        domains = _collect_domains(parsed, url_a)
        assert "example.com" in domains

    def test_url_domains_included(self):
        parsed = _make_parsed("example.com")
        url_a  = _make_url_analysis(["evil.xyz", "phish.co.in"])
        domains = _collect_domains(parsed, url_a)
        assert "evil.xyz" in domains
        assert "phish.co.in" in domains

    def test_ip_addresses_excluded(self):
        parsed = _make_parsed("185.234.219.47")   # IP as domain
        url_a  = _make_url_analysis(["1.2.3.4"])
        domains = _collect_domains(parsed, url_a)
        assert "185.234.219.47" not in domains
        assert "1.2.3.4" not in domains

    def test_duplicates_deduplicated(self):
        parsed = _make_parsed("example.com")
        url_a  = _make_url_analysis(["example.com", "example.com", "other.com"])
        domains = _collect_domains(parsed, url_a)
        assert domains.count("example.com") == 1

    def test_empty_domain_excluded(self):
        parsed = _make_parsed("")
        url_a  = _make_url_analysis([""])
        domains = _collect_domains(parsed, url_a)
        assert "" not in domains

    def test_case_normalized_to_lowercase(self):
        parsed = _make_parsed("EXAMPLE.COM")
        url_a  = _make_url_analysis([])
        domains = _collect_domains(parsed, url_a)
        assert "example.com" in domains
        assert "EXAMPLE.COM" not in domains


# ═══════════════════════════════════════════════════════════════════
# 2. Current DNS Normalization
# ═══════════════════════════════════════════════════════════════════
class TestCurrentDNSParsing:
    def test_a_records_preserved(self):
        raw = _minimal_raw(a_records=["1.2.3.4", "5.6.7.8"])
        result = _normalize("example.com", raw, "Mock/Demo")
        assert "1.2.3.4" in result.current_dns.A
        assert "5.6.7.8" in result.current_dns.A

    def test_empty_record_types_are_empty_lists(self):
        raw = _minimal_raw()
        result = _normalize("example.com", raw, "Mock/Demo")
        assert result.current_dns.AAAA == []
        assert result.current_dns.MX == []
        assert result.current_dns.NS == []

    def test_returns_dns_record_set_type(self):
        raw = _minimal_raw()
        result = _normalize("example.com", raw, "Mock/Demo")
        assert isinstance(result.current_dns, DNSRecordSet)


# ═══════════════════════════════════════════════════════════════════
# 3. Historical DNS Normalization
# ═══════════════════════════════════════════════════════════════════
class TestHistoricalDNSNormalization:
    def test_historical_a_records_parsed(self):
        raw = _minimal_raw(hist_a=[
            {"value": "10.20.30.40", "first_seen": "2024-01-01", "last_seen": "2024-06-01"}
        ])
        result = _normalize("example.com", raw, "Mock/Demo")
        assert len(result.historical_dns["A"]) == 1
        rec = result.historical_dns["A"][0]
        assert isinstance(rec, HistoricalDNSRecord)
        assert rec.value == "10.20.30.40"
        assert rec.first_seen == "2024-01-01"

    def test_missing_historical_dns_returns_empty(self):
        raw = _minimal_raw()
        result = _normalize("example.com", raw, "Mock/Demo")
        for rtype in ("A", "AAAA", "MX", "NS", "CNAME"):
            assert result.historical_dns[rtype] == []

    def test_records_with_no_value_excluded(self):
        raw = _minimal_raw(hist_a=[{"value": "", "first_seen": "2024-01-01"}])
        result = _normalize("example.com", raw, "Mock/Demo")
        assert result.historical_dns["A"] == []


# ═══════════════════════════════════════════════════════════════════
# 4. Historical IP Normalization
# ═══════════════════════════════════════════════════════════════════
class TestHistoricalIPNormalization:
    def test_historical_ips_parsed(self):
        raw = _minimal_raw(hist_ips=[
            {"ip": "91.219.236.14", "first_seen": "2024-05-10", "last_seen": "2024-06-01"}
        ])
        result = _normalize("example.com", raw, "Mock/Demo")
        assert len(result.historical_ips) == 1
        hip = result.historical_ips[0]
        assert isinstance(hip, HistoricalIP)
        assert hip.ip == "91.219.236.14"
        assert hip.first_seen == "2024-05-10"

    def test_empty_ip_string_excluded(self):
        raw = _minimal_raw(hist_ips=[{"ip": "", "first_seen": "2024-01-01"}])
        result = _normalize("example.com", raw, "Mock/Demo")
        assert result.historical_ips == []

    def test_none_timestamps_are_none(self):
        raw = _minimal_raw(hist_ips=[{"ip": "1.2.3.4", "first_seen": None, "last_seen": None}])
        result = _normalize("example.com", raw, "Mock/Demo")
        assert result.historical_ips[0].first_seen is None


# ═══════════════════════════════════════════════════════════════════
# 5. WHOIS History Normalization
# ═══════════════════════════════════════════════════════════════════
class TestWhoisHistoryNormalization:
    def test_whois_record_parsed(self):
        raw = _minimal_raw(whois=[{
            "registrar": "GoDaddy LLC",
            "registered": "2024-01-01",
            "updated": "2024-06-01",
            "expires": "2025-01-01",
            "nameservers": ["ns1.example.com"],
        }])
        result = _normalize("example.com", raw, "Mock/Demo")
        assert len(result.whois_history) == 1
        w = result.whois_history[0]
        assert isinstance(w, WhoisRecord)
        assert w.registrar == "GoDaddy LLC"
        assert w.nameservers == ["ns1.example.com"]

    def test_empty_whois_returns_empty_list(self):
        raw = _minimal_raw()
        result = _normalize("example.com", raw, "Mock/Demo")
        assert result.whois_history == []


# ═══════════════════════════════════════════════════════════════════
# 6. Security Detection Parsing
# ═══════════════════════════════════════════════════════════════════
class TestSecurityDetectionParsing:
    def test_current_detection_parsed(self):
        raw = _minimal_raw(
            curr_detected=True,
            detections=[{"date": "2026-01-01", "category": "Phishing", "provider": "Mock/Demo"}],
        )
        result = _normalize("example.com", raw, "Mock/Demo")
        assert result.security_history.currently_detected is True
        assert len(result.security_history.detections) == 1
        assert result.security_history.detections[0].category == "Phishing"

    def test_not_detected_is_false_not_malicious(self):
        raw = _minimal_raw(prev_detected=False, curr_detected=False)
        result = _normalize("example.com", raw, "Mock/Demo")
        assert result.security_history.previously_detected is False
        assert result.security_history.currently_detected is False
        assert result.security_history.detections == []

    def test_security_history_is_typed(self):
        raw = _minimal_raw()
        result = _normalize("example.com", raw, "Mock/Demo")
        assert isinstance(result.security_history, SecurityHistory)


# ═══════════════════════════════════════════════════════════════════
# 7. Timeline Generation
# ═══════════════════════════════════════════════════════════════════
class TestTimelineGeneration:
    def test_whois_registration_creates_event(self):
        raw = _minimal_raw(whois=[{
            "registrar": "Test Registrar",
            "registered": "2024-05-01",
            "updated": None,
            "expires": None,
            "nameservers": [],
        }])
        result = _normalize("example.com", raw, "Mock/Demo")
        events = [e for e in result.timeline if e.event == "Domain registered"]
        assert len(events) == 1
        assert events[0].date == "2024-05-01"

    def test_ip_observed_creates_event(self):
        raw = _minimal_raw(hist_ips=[
            {"ip": "1.2.3.4", "first_seen": "2024-06-01", "last_seen": "2024-07-01"}
        ])
        result = _normalize("example.com", raw, "Mock/Demo")
        events = [e for e in result.timeline if e.event == "IP observed"]
        assert len(events) == 1

    def test_security_detection_creates_event(self):
        raw = _minimal_raw(
            curr_detected=True,
            detections=[{"date": "2026-03-15", "category": "Malware", "provider": "Mock/Demo"}],
        )
        result = _normalize("example.com", raw, "Mock/Demo")
        events = [e for e in result.timeline if e.event == "Security detection observed"]
        assert len(events) == 1
        assert events[0].value == "Malware"

    def test_no_date_means_no_timeline_event(self):
        """Events without timestamps must NOT be added to the timeline."""
        raw = _minimal_raw(hist_ips=[
            {"ip": "9.8.7.6", "first_seen": None, "last_seen": None}
        ])
        result = _normalize("example.com", raw, "Mock/Demo")
        # No first_seen → no IP observed event
        events = [e for e in result.timeline if e.event == "IP observed"]
        assert len(events) == 0


# ═══════════════════════════════════════════════════════════════════
# 8. Chronological Sorting
# ═══════════════════════════════════════════════════════════════════
class TestChronologicalSorting:
    def test_timeline_is_sorted_chronologically(self):
        raw = _minimal_raw(
            hist_ips=[
                {"ip": "3.3.3.3", "first_seen": "2026-06-01", "last_seen": "2026-07-01"},
                {"ip": "1.1.1.1", "first_seen": "2024-01-01", "last_seen": "2024-06-01"},
                {"ip": "2.2.2.2", "first_seen": "2025-03-15", "last_seen": "2025-04-01"},
            ],
            whois=[{
                "registrar": "Reg",
                "registered": "2023-11-01",
                "updated": None, "expires": None, "nameservers": [],
            }],
        )
        result = _normalize("example.com", raw, "Mock/Demo")
        dates = [e.date for e in result.timeline if e.date]
        assert dates == sorted(dates), f"Timeline not sorted: {dates}"


# ═══════════════════════════════════════════════════════════════════
# 9. Duplicate Domain Handling
# ═══════════════════════════════════════════════════════════════════
class TestDuplicateDomainHandling:
    def test_same_domain_in_multiple_urls_analyzed_once(self):
        """Per-request cache: same domain in sender + 3 URLs → 1 investigation."""
        parsed = _make_parsed("example.com")
        url_a  = _make_url_analysis(["example.com", "example.com", "example.com"])

        call_count = {"n": 0}
        original_get = MockDomainIntelligenceProvider.get_forensic_data

        def counting_get(self, domain):
            call_count["n"] += 1
            return original_get(self, domain)

        with patch.object(MockDomainIntelligenceProvider, "get_forensic_data", counting_get):
            with patch.object(forensic_domain_intelligence, "config") as mock_cfg:
                mock_cfg.FORENSIC_MOCK_MODE = True
                result = run_forensic_domain_analysis(parsed, url_a)

        # Only 1 unique domain → only 1 provider call
        assert call_count["n"] == 1
        assert len(result.domains) == 1

    def test_different_domains_all_analyzed(self):
        parsed = _make_parsed("alpha.com")
        url_a  = _make_url_analysis(["beta.com", "gamma.com"])
        result = run_forensic_domain_analysis(parsed, url_a)
        analyzed = {d.domain for d in result.domains}
        assert "alpha.com" in analyzed
        assert "beta.com"  in analyzed
        assert "gamma.com" in analyzed


# ═══════════════════════════════════════════════════════════════════
# 10. Missing Provider Data
# ═══════════════════════════════════════════════════════════════════
class TestMissingProviderData:
    def test_unknown_domain_returns_empty_not_fake(self):
        """Domain not in mock DB → structured empty, not fabricated data."""
        result = get_forensic_domain_intel("this-domain-does-not-exist-xyz123.com")
        assert result.current_dns.A == []
        assert result.historical_ips == []
        assert result.whois_history == []
        assert result.security_history.previously_detected is False
        assert result.security_history.currently_detected is False

    def test_unknown_domain_has_limitation_note(self):
        result = get_forensic_domain_intel("not-in-mock-db.example")
        assert len(result.limitations) > 0

    def test_unknown_domain_data_source_is_mock(self):
        result = get_forensic_domain_intel("totally-unknown-9999.xyz")
        assert result.data_source == "Mock/Demo"


# ═══════════════════════════════════════════════════════════════════
# 11. API Unavailable
# ═══════════════════════════════════════════════════════════════════
class TestAPIUnavailable:
    def test_unavailable_provider_returns_empty_not_error(self):
        provider = _UnavailableProvider()
        raw = provider.get_forensic_data("example.com")
        result = _normalize("example.com", raw, "Unavailable")
        assert result.data_source == "Unavailable"
        assert result.current_dns.A == []
        assert result.historical_ips == []

    def test_unavailable_provider_has_limitation_message(self):
        provider = _UnavailableProvider()
        raw = provider.get_forensic_data("example.com")
        result = _normalize("example.com", raw, "Unavailable")
        assert len(result.limitations) > 0
        assert "not configured" in result.limitations[0].lower()

    def test_unavailable_provider_security_history_false(self):
        provider = _UnavailableProvider()
        raw = provider.get_forensic_data("example.com")
        result = _normalize("example.com", raw, "Unavailable")
        assert result.security_history.previously_detected is False
        assert result.security_history.currently_detected is False


# ═══════════════════════════════════════════════════════════════════
# 12. Mock Provider Correctness
# ═══════════════════════════════════════════════════════════════════
class TestMockProvider:
    def test_known_phishing_domain_has_detection(self):
        result = get_forensic_domain_intel("hdfcbank-secure.co.in")
        assert result.data_source == "Mock/Demo"
        assert result.security_history.currently_detected is True
        assert len(result.security_history.detections) > 0

    def test_known_phishing_domain_has_historical_ip(self):
        result = get_forensic_domain_intel("hdfcbank-secure.co.in")
        assert len(result.historical_ips) >= 1

    def test_known_phishing_domain_has_current_dns(self):
        result = get_forensic_domain_intel("hdfcbank-secure.co.in")
        assert len(result.current_dns.A) >= 1

    def test_known_phishing_domain_has_whois(self):
        result = get_forensic_domain_intel("hdfcbank-secure.co.in")
        assert len(result.whois_history) >= 1

    def test_clean_domain_no_detections(self):
        result = get_forensic_domain_intel("github.com")
        assert result.security_history.previously_detected is False
        assert result.security_history.currently_detected is False
        assert result.security_history.detections == []

    def test_data_source_label_is_mock(self):
        result = get_forensic_domain_intel("hdfcbank-secure.co.in")
        assert "Mock" in result.data_source or "Demo" in result.data_source


# ═══════════════════════════════════════════════════════════════════
# 13. No Fabricated Data
# ═══════════════════════════════════════════════════════════════════
class TestNoFabricatedData:
    def test_unknown_domain_has_empty_detections(self):
        result = get_forensic_domain_intel("absolutely-unknown-domain-xyz.io")
        assert result.security_history.detections == []

    def test_unknown_domain_has_empty_timeline(self):
        result = get_forensic_domain_intel("absolutely-unknown-domain-xyz.io")
        # Empty mock DB → no events with real timestamps should be generated
        assert result.timeline == []

    def test_unknown_domain_has_empty_whois(self):
        result = get_forensic_domain_intel("absolutely-unknown-domain-xyz.io")
        assert result.whois_history == []

    def test_mock_source_never_claims_real_provider(self):
        result = get_forensic_domain_intel("hdfcbank-secure.co.in")
        assert "VirusTotal" not in result.data_source
        assert "SecurityTrails" not in result.data_source

    def test_result_is_json_serializable(self):
        import json
        result = get_forensic_domain_intel("hdfcbank-secure.co.in")
        # Manually serialize the key fields to confirm no non-serializable types
        d = {
            "domain":      result.domain,
            "data_source": result.data_source,
            "timeline": [
                {"date": e.date, "event": e.event, "value": e.value, "source": e.source}
                for e in result.timeline
            ],
            "historical_ips": [
                {"ip": h.ip, "first_seen": h.first_seen, "last_seen": h.last_seen}
                for h in result.historical_ips
            ],
            "limitations":  result.limitations,
        }
        serialized = json.dumps(d, ensure_ascii=False)
        assert len(serialized) > 10


# ═══════════════════════════════════════════════════════════════════
# 14. End-to-End Integration
# ═══════════════════════════════════════════════════════════════════
class TestEndToEndForensicsIntegration:
    def test_phishing_email_has_forensics_key(self):
        from pathlib import Path
        from ..main import analyze_email
        eml = (Path(__file__).parent.parent / "sample_emails" / "phishing_bank.eml").read_text()
        result = analyze_email(eml)
        assert "forensics" in result

    def test_forensics_has_domains_list(self):
        from pathlib import Path
        from ..main import analyze_email
        eml = (Path(__file__).parent.parent / "sample_emails" / "phishing_bank.eml").read_text()
        result = analyze_email(eml)
        assert "domains" in result["forensics"]
        assert isinstance(result["forensics"]["domains"], list)

    def test_each_domain_has_required_keys(self):
        from pathlib import Path
        from ..main import analyze_email
        eml = (Path(__file__).parent.parent / "sample_emails" / "phishing_bank.eml").read_text()
        result = analyze_email(eml)
        required = [
            "domain", "data_source", "current_dns", "historical_dns",
            "historical_ips", "whois_history", "security_history",
            "timeline", "evidence", "limitations",
        ]
        for d in result["forensics"]["domains"]:
            for key in required:
                assert key in d, f"Missing key '{key}' in forensic domain entry"

    def test_forensics_does_not_break_existing_keys(self):
        from pathlib import Path
        from ..main import analyze_email
        eml = (Path(__file__).parent.parent / "sample_emails" / "legitimate.eml").read_text()
        result = analyze_email(eml)
        # All original keys still present
        for key in ("threat_score", "verdict", "email", "authentication",
                    "infrastructure", "domain", "urls", "attachments", "ml",
                    "evidence", "positive_evidence", "limitations"):
            assert key in result, f"Original key '{key}' missing after forensics integration"

    def test_phishing_email_forensics_is_json_serializable(self):
        import json
        from pathlib import Path
        from ..main import analyze_email
        eml = (Path(__file__).parent.parent / "sample_emails" / "phishing_bank.eml").read_text()
        result = analyze_email(eml)
        serialized = json.dumps(result["forensics"], ensure_ascii=False)
        assert len(serialized) > 50

    def test_legitimate_email_forensics_has_clean_domain(self):
        from pathlib import Path
        from ..main import analyze_email
        eml = (Path(__file__).parent.parent / "sample_emails" / "legitimate.eml").read_text()
        result = analyze_email(eml)
        domains = result["forensics"]["domains"]
        github_entries = [d for d in domains if "github" in d["domain"]]
        if github_entries:
            gh = github_entries[0]
            assert gh["security_history"]["currently_detected"] is False
