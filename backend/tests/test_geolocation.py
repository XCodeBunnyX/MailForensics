"""
Unit tests for GmailGuard IPinfo Geolocation Module.

Tests cover all 10 specific requirements:
1. Valid public IP
2. Private IP is rejected/not queried
3. Invalid IP
4. Successful IPinfo response
5. Missing API token
6. API timeout
7. HTTP/API error
8. Multiple unique IPs
9. Duplicate IPs are not unnecessarily queried
10. Missing optional location fields
"""

import io
import json
import socket
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from .. import config
from ..geolocation import (
    GeoRecord,
    clear_geo_cache,
    geolocate_ips,
    get_ip_geolocation,
    get_ip_geolocation_record,
    is_public_ip,
)
from ..evidence_correlator import correlate_evidence
from ..ml_classifier import MLResult
from ..authentication_analyzer import AuthResult
from ..ip_intelligence import IPIntelligence, IPRecord
from ..domain_intelligence import DomainIntelligence
from ..url_analyzer import URLAnalysis
from ..attachment_analyzer import AttachmentAnalysis


@pytest.fixture(autouse=True)
def reset_cache_and_env(monkeypatch):
    """Ensure a clean in-memory cache and predictable environment for each test."""
    clear_geo_cache()
    monkeypatch.setattr(config, "IPINFO_TOKEN", "mock_test_token_xyz")
    yield
    clear_geo_cache()


def _mock_response(data: dict, status_code: int = 200):
    """Helper to generate a mock urllib response."""
    raw_bytes = json.dumps(data).encode("utf-8")
    resp = MagicMock()
    resp.read.return_value = raw_bytes
    resp.status = status_code
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


# ── Test 1: Valid Public IP ───────────────────────────────────────

def test_valid_public_ip_parsing():
    """Requirement 1: Valid public IP queries IPinfo and returns normalized fields."""
    mock_payload = {
        "ip": "76.223.181.101",
        "city": "Pune",
        "region": "Maharashtra",
        "country": "IN",
        "loc": "18.5204,73.8567",
        "org": "AS13335 Cloudflare, Inc.",
        "postal": "411001",
        "timezone": "Asia/Kolkata",
        "hostname": "relay.example.com",
    }

    with patch("urllib.request.urlopen", return_value=_mock_response(mock_payload)) as mock_call:
        res = get_ip_geolocation("76.223.181.101")

        assert mock_call.called
        assert res["status"] == "success"
        assert res["ip"] == "76.223.181.101"
        assert res["country"] == "IN"
        assert res["region"] == "Maharashtra"
        assert res["city"] == "Pune"
        assert res["latitude"] == pytest.approx(18.5204)
        assert res["longitude"] == pytest.approx(73.8567)
        assert res["asn"] == "AS13335"
        assert res["organization"] == "Cloudflare, Inc."
        assert res["postal"] == "411001"
        assert res["timezone"] == "Asia/Kolkata"
        assert res["hostname"] == "relay.example.com"
        assert res["source"] == "IPinfo"
        assert res["location_type"] == "observable_infrastructure"
        assert "approximate" in res["location_note"].lower()
        assert "physical location" in res["location_note"].lower()
        # Must not claim attacker location
        assert "attacker" not in res["forensic_note"].lower()
        assert "Pune, Maharashtra, IN" in res["forensic_note"]


# ── Test 2: Private IP is Rejected / Not Queried ───────────────────

@pytest.mark.parametrize("private_ip", [
    "10.0.0.1",
    "10.255.255.254",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
    "192.168.1.254",
    "127.0.0.1",
    "169.254.1.1",
    "::1",
    "fc00::1",
])
def test_private_ips_rejected_without_query(private_ip):
    """Requirement 2: Private, loopback, and reserved IPs are never sent to IPinfo."""
    with patch("urllib.request.urlopen") as mock_call:
        res = get_ip_geolocation(private_ip)
        assert not mock_call.called, f"API should not be called for private IP {private_ip}"
        assert res["status"] == "rejected"
        assert res["reason"] == "Private or reserved IP address"
        assert res["ip"] == private_ip
        assert res["source"] == "IPinfo"


# ── Test 3: Invalid IP Format ──────────────────────────────────────

@pytest.mark.parametrize("invalid_ip", [
    "999.999.999.999",
    "not-an-ip",
    "1.2.3.4.5",
    "256.1.1.1",
    "",
    "   ",
])
def test_invalid_ip_format(invalid_ip):
    """Requirement 3: Invalid IP strings fail validation without making API calls."""
    with patch("urllib.request.urlopen") as mock_call:
        res = get_ip_geolocation(invalid_ip)
        assert not mock_call.called
        assert res["status"] == "error"
        assert "Invalid IP address" in res["reason"]


# ── Test 4: Successful IPinfo Response to GeoRecord ────────────────

def test_successful_ipinfo_response_record():
    """Requirement 4: Data maps cleanly to GeoRecord with backwards compatibility."""
    mock_payload = {
        "ip": "8.8.8.8",
        "city": "Mountain View",
        "region": "California",
        "country": "US",
        "loc": "37.4056,-122.0775",
        "org": "AS15169 Google LLC",
        "postal": "94043",
        "timezone": "America/Los_Angeles",
    }

    with patch("urllib.request.urlopen", return_value=_mock_response(mock_payload)):
        rec = get_ip_geolocation_record("8.8.8.8")
        assert isinstance(rec, GeoRecord)
        assert rec.ip == "8.8.8.8"
        assert rec.lat == pytest.approx(37.4056)
        assert rec.lon == pytest.approx(-122.0775)
        assert rec.latitude == rec.lat
        assert rec.longitude == rec.lon
        assert rec.asn == "AS15169"
        assert rec.org == "Google LLC"
        assert rec.organization == "Google LLC"
        assert rec.status == "success"
        assert rec.source == "IPinfo"

        d = rec.to_dict()
        assert d["ip"] == "8.8.8.8"
        assert d["city"] == "Mountain View"
        assert d["location_type"] == "observable_infrastructure"


# ── Test 5: Missing API Token ──────────────────────────────────────

def test_missing_api_token(monkeypatch):
    """Requirement 5: Missing token returns structured unavailable result without crashing."""
    monkeypatch.setattr(config, "IPINFO_TOKEN", "")
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)

    with patch("urllib.request.urlopen") as mock_call:
        res = get_ip_geolocation("8.8.8.8")
        assert not mock_call.called
        assert res["status"] == "unavailable"
        assert res["reason"] == "IPinfo API token is not configured"
        assert res["source"] == "IPinfo"
        assert res["ip"] == "8.8.8.8"


# ── Test 6: API Timeout ───────────────────────────────────────────

def test_api_timeout():
    """Requirement 6: Network timeouts return unavailable status gracefully."""
    with patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
        res = get_ip_geolocation("8.8.8.8")
        assert res["status"] == "unavailable"
        assert "timed out" in res["reason"].lower()
        assert res["source"] == "IPinfo"


# ── Test 7: HTTP / API Errors ─────────────────────────────────────

def test_api_http_unauthorized():
    """Requirement 7a: HTTP 401/403 authentication failure handled gracefully."""
    err = urllib.error.HTTPError("https://ipinfo.io/8.8.8.8/json", 401, "Unauthorized", {}, None)
    with patch("urllib.request.urlopen", side_effect=err):
        res = get_ip_geolocation("8.8.8.8")
        assert res["status"] in ("error", "unavailable")
        assert "authentication failed" in res["reason"].lower()
        # Never leak the actual token
        assert "mock_test_token" not in str(res)


def test_api_http_rate_limit():
    """Requirement 7b: HTTP 429 rate limiting handled gracefully."""
    err = urllib.error.HTTPError("https://ipinfo.io/8.8.8.8/json", 429, "Too Many Requests", {}, None)
    with patch("urllib.request.urlopen", side_effect=err):
        res = get_ip_geolocation("8.8.8.8")
        assert res["status"] == "unavailable"
        assert "rate limit" in res["reason"].lower()


def test_api_http_server_error():
    """Requirement 7c: HTTP 500 error handled gracefully without crashing."""
    err = urllib.error.HTTPError("https://ipinfo.io/8.8.8.8/json", 500, "Internal Server Error", {}, None)
    with patch("urllib.request.urlopen", side_effect=err):
        res = get_ip_geolocation("8.8.8.8")
        assert res["status"] == "error"
        assert "HTTP error 500" in res["reason"]


# ── Test 8: Multiple Unique IPs ────────────────────────────────────

def test_multiple_unique_ips():
    """Requirement 8: Multiple unique public IPs are each geolocated."""
    def side_effect(req, *args, **kwargs):
        url = req.full_url
        if "8.8.8.8" in url:
            return _mock_response({"ip": "8.8.8.8", "country": "US", "city": "Mountain View"})
        elif "1.1.1.1" in url:
            return _mock_response({"ip": "1.1.1.1", "country": "AU", "city": "Sydney"})
        return _mock_response({"ip": "unknown"})

    with patch("urllib.request.urlopen", side_effect=side_effect) as mock_call:
        records = geolocate_ips(["8.8.8.8", "1.1.1.1"])
        assert len(records) == 2
        assert mock_call.call_count == 2
        assert records[0].ip == "8.8.8.8"
        assert records[0].country == "US"
        assert records[1].ip == "1.1.1.1"
        assert records[1].country == "AU"


# ── Test 9: Duplicate IPs Not Queried Repeatedly (Caching) ─────────

def test_duplicate_ips_cached():
    """Requirement 9: Duplicate IPs in email headers only trigger a single API query."""
    mock_payload = {"ip": "8.8.8.8", "country": "US", "city": "Mountain View"}

    with patch("urllib.request.urlopen", return_value=_mock_response(mock_payload)) as mock_call:
        # Pass 3 identical IPs
        records = geolocate_ips(["8.8.8.8", "8.8.8.8", "8.8.8.8"])
        assert len(records) == 3
        # URL open must be called only ONCE due to in-memory caching
        assert mock_call.call_count == 1
        for r in records:
            assert r.ip == "8.8.8.8"
            assert r.country == "US"


# ── Test 10: Missing Optional Location Fields ─────────────────────

def test_missing_optional_location_fields():
    """Requirement 10: Minimal/sparse IPinfo responses don't cause KeyErrors or fabricated values."""
    mock_payload = {
        "ip": "76.223.181.101",
        # Missing: city, region, country, loc, postal, timezone, org, hostname
    }

    with patch("urllib.request.urlopen", return_value=_mock_response(mock_payload)):
        res = get_ip_geolocation("76.223.181.101")
        assert res["status"] == "success"
        assert res["country"] == "UNKNOWN"
        assert res["region"] == "UNKNOWN"
        assert res["city"] == "UNKNOWN"
        assert res["latitude"] is None
        assert res["longitude"] is None
        assert res["postal"] is None
        assert res["timezone"] is None
        assert res["asn"] == "UNKNOWN"
        assert res["organization"] == "UNKNOWN"
        assert res["hostname"] is None


# ── Test 11: Evidence Correlation Integration ──────────────────────

def test_evidence_correlation_with_geolocation():
    """Verify IPinfo results appear as supporting contextual evidence in evidence correlation."""
    geo_rec = GeoRecord(
        ip="76.223.181.101",
        country="India",
        region="Maharashtra",
        city="Pune",
        lat=18.5204,
        lon=73.8567,
        asn="AS13335",
        org="Cloudflare, Inc.",
        source="IPinfo",
        status="success",
    )

    ml = MLResult(prediction="Legitimate", decision_score=-0.5, model_available=True, note="Legitimate text patterns")
    auth = AuthResult(
        spf="PASS",
        dkim="PASS",
        dmarc="PASS",
        spf_detail="",
        dkim_detail="",
        dmarc_detail="",
        all_passed=True,
        any_failed=False,
        summary="All authentication checks passed",
    )
    ip_intel = IPIntelligence(
        public_ips=["76.223.181.101"],
        records=[],
        any_malicious=False,
        any_suspicious=False,
        max_reputation_score=0,
        limitations=[],
    )
    domain_intel = DomainIntelligence(
        domain="example.com",
        reputation="clean",
        reputation_score=0,
        categories=[],
        age_days=300,
        registrar="Example Registrar",
        virustotal_flags=0,
        is_suspicious_tld=False,
        tld="com",
        is_typosquat=False,
        typosquat_target="",
        risk_score=0,
        reasons=[],
        source="whois",
    )
    url_analysis = URLAnalysis(
        total_count=0,
        suspicious_count=0,
        findings=[],
        all_urls=[],
        limitations=[],
    )
    att_analysis = AttachmentAnalysis(
        total_count=0,
        suspicious_count=0,
        findings=[],
    )

    evidence = correlate_evidence(
        ml=ml,
        auth=auth,
        ip_intel=ip_intel,
        domain_intel=domain_intel,
        url_analysis=url_analysis,
        att_analysis=att_analysis,
        geo_records=[geo_rec],
    )

    ipinfo_ev = [e for e in evidence if e["source"] == "IPinfo"]
    assert len(ipinfo_ev) == 1
    item = ipinfo_ev[0]
    assert item["severity"] == "info"
    assert "Pune, Maharashtra, India" in item["finding"]
    assert "AS13335" in item["finding"]
    assert "Cloudflare, Inc." in item["finding"]
    assert "sender's physical location" in item["finding"]


# ── Test 12: Security - Token Is Never Leaked ──────────────────────

def test_token_is_never_leaked():
    """Security rule: Token must never appear in response dicts, string representations, or error notes."""
    secret_token = "super_secret_production_token_12345"
    with patch.object(config, "IPINFO_TOKEN", secret_token):
        mock_payload = {"ip": "8.8.8.8", "country": "US"}
        with patch("urllib.request.urlopen", return_value=_mock_response(mock_payload)):
            res = get_ip_geolocation("8.8.8.8")
            res_str = json.dumps(res)
            assert secret_token not in res_str

        # Test error case
        err = urllib.error.HTTPError("https://ipinfo.io/8.8.8.8/json", 403, "Forbidden", {}, None)
        with patch("urllib.request.urlopen", side_effect=err):
            clear_geo_cache()
            res_err = get_ip_geolocation("8.8.8.8")
            res_err_str = json.dumps(res_err)
            assert secret_token not in res_err_str
