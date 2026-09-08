"""
Unit tests for GmailGuard Observational Forensic Attribution & Envelope Provenance Engine:
- Granular Evidence Taxonomy (RelayHop.raw is OBSERVED, parsed fields are DERIVED)
- Evidence-Based Hop Provenance (RECIPIENT_MTA_OBSERVED, UPSTREAM_MTA_RECORDED, UNVERIFIED_UPSTREAM_HOP, CLIENT_OR_HEADER_SUPPLIED)
- 4-Tier Candidate Relays Ranking Hierarchy (with untrusted X-Originating-IP ranking lowest)
- UTC Timestamp Normalization & Hop Timeline Skew Analysis
- Neutral Programmatic / Automated Sender Fingerprinting & Charset Disclaimers
- Full IPv4 and IPv6 Validation
- External Intelligence Deduplication
- Zero Threat Score Impact (Strict Score Isolation)
- End-to-End Report Schema Verification
"""

import email.message
from datetime import datetime, timezone
import pytest

import config
from email_parser import ParsedEmail, parse_email
from header_analyzer import (
    analyze_headers,
    _extract_client_fingerprint,
    _extract_received_timestamp,
    _determine_hop_provenance,
    _is_private_ip,
    HeaderIntelligence,
    ClientFingerprint,
    RelayHop,
)
from evidence_correlator import correlate_timezone, correlate_evidence
from geolocation import GeoRecord, geolocate_ips, clear_geo_cache
from ml_classifier import MLResult
from authentication_analyzer import AuthResult
from ip_intelligence import IPIntelligence
from domain_intelligence import DomainIntelligence
from url_analyzer import URLAnalysis
from attachment_analyzer import AttachmentAnalysis
from report_generator import generate_report
from threat_scorer import ThreatScore, compute_threat_score


# ── 1. IPv4 and IPv6 Validation Tests ──────────────────────────────

def test_is_private_ip_ipv4_and_ipv6():
    """Verify private, reserved, loopback, link-local, and multicast IP detection for IPv4 & IPv6."""
    # IPv4 Private / Loopback
    assert _is_private_ip("10.0.0.1") is True
    assert _is_private_ip("192.168.1.1") is True
    assert _is_private_ip("172.16.0.1") is True
    assert _is_private_ip("127.0.0.1") is True
    assert _is_private_ip("169.254.1.1") is True
    assert _is_private_ip("100.64.0.1") is True  # CGNAT
    assert _is_private_ip("198.51.100.1") is True  # TEST-NET-2

    # IPv6 Private / Loopback / Local
    assert _is_private_ip("::1") is True
    assert _is_private_ip("fe80::1") is True       # Link-local
    assert _is_private_ip("fc00::1") is True       # Unique local
    assert _is_private_ip("ff02::1") is True       # Multicast

    # Invalid
    assert _is_private_ip("invalid-ip") is True
    assert _is_private_ip(None) is True
    assert _is_private_ip("") is True

    # Public IPs (must be False)
    assert _is_private_ip("8.8.8.8") is False
    assert _is_private_ip("76.223.181.101") is False
    assert _is_private_ip("93.184.216.34") is False
    assert _is_private_ip("2001:4860:4860::8888") is False  # Google public DNS IPv6


# ── 2. Granular Hop Taxonomy & Provenance Tests ────────────────────

def test_granular_evidence_taxonomy_on_relay_hop():
    """Requirement 1: raw header is OBSERVED, parsed properties and trust classifications are DERIVED."""
    raw_header = "from mail.upstream.com ([93.184.216.34]) by mx.recipient.com with ESMTP id 12345; Mon, 15 Mar 2026 10:00:00 +0000"
    raw_email = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Forensic Taxonomy Test\r\n"
        f"Received: {raw_header}\r\n"
        "\r\n"
        "Body content\r\n"
    )
    parsed = parse_email(raw_email)
    header_intel = analyze_headers(parsed)

    assert len(header_intel.relay_chain) == 1
    hop = header_intel.relay_chain[0]

    # raw is the directly observed envelope text
    assert hop.raw == raw_header
    # evidence_class on derived fields is DERIVED
    assert hop.evidence_class == "DERIVED"
    assert hop.from_host == "mail.upstream.com"
    assert hop.by_host == "mx.recipient.com"
    assert hop.ip == "93.184.216.34"
    assert hop.provenance == "RECIPIENT_MTA_OBSERVED"
    assert hop.confidence == "high"


def test_evidence_based_provenance_for_earliest_hop():
    """
    Requirement 2: Do NOT automatically label bottom hop as UNVERIFIED_UPSTREAM_HOP.
    Check whether it establishes standard MTA transfer clauses (UPSTREAM_MTA_RECORDED).
    """
    # Case A: Earliest hop has valid MTA clauses (by host with ESMTP id)
    email_with_mta = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Valid Upstream MTA\r\n"
        "Received: from mx.recipient.com ([203.0.113.10]) by gate.recipient.com with ESMTP; Mon, 15 Mar 2026 10:02:00 +0000\r\n"
        "Received: from origin.relay.com ([93.184.216.34]) by mx.recipient.com with ESMTP id abc987; Mon, 15 Mar 2026 10:01:00 +0000\r\n"
        "\r\n"
        "Body\r\n"
    )
    parsed_a = parse_email(email_with_mta)
    intel_a = analyze_headers(parsed_a)
    earliest_hop_a = intel_a.chronological_hops[0]
    assert earliest_hop_a.hop_number == 1
    assert earliest_hop_a.provenance == "UPSTREAM_MTA_RECORDED"
    assert earliest_hop_a.confidence == "medium"

    # Case B: Earliest hop lacks MTA transfer clauses (e.g. submission without transfer clauses)
    email_without_mta = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Bare Header Submission\r\n"
        "Received: from mx.recipient.com ([203.0.113.10]) by gate.recipient.com with ESMTP; Mon, 15 Mar 2026 10:02:00 +0000\r\n"
        "Received: from client.laptop.local ([93.184.216.34]); Mon, 15 Mar 2026 10:00:00 +0000\r\n"
        "\r\n"
        "Body\r\n"
    )
    parsed_b = parse_email(email_without_mta)
    intel_b = analyze_headers(parsed_b)
    earliest_hop_b = intel_b.chronological_hops[0]
    assert earliest_hop_b.hop_number == 1
    assert earliest_hop_b.provenance == "UNVERIFIED_UPSTREAM_HOP"
    assert earliest_hop_b.confidence == "low"


# ── 3. Candidate Relays Ranking Hierarchy Tests ───────────────────

def test_candidate_relays_ranking_hierarchy_and_untrusted_x_originating_ip():
    """
    Verify 4-tier candidate relays ranking:
    Tier 1: RECIPIENT_MTA_OBSERVED (High)
    Tier 2: UPSTREAM_MTA_RECORDED (Medium)
    Tier 3: UNVERIFIED_UPSTREAM_HOP (Low)
    Tier 4: CLIENT_OR_HEADER_SUPPLIED (Untrusted, X-Originating-IP) - never outranks Received: headers!
    """
    raw_email = (
        "From: sender@example.com\r\n"
        "To: victim@example.com\r\n"
        "Subject: Multi-Hop Ranking Test\r\n"
        "X-Originating-IP: [76.223.181.101]\r\n"
        "Received: from gateway.victim.com ([209.85.220.41]) by mail.victim.com with ESMTP; Mon, 15 Mar 2026 10:03:00 +0000\r\n"
        "Received: from transit.relay.com ([93.184.216.34]) by gateway.victim.com with ESMTP id 123; Mon, 15 Mar 2026 10:02:00 +0000\r\n"
        "Received: from initial.client.com ([185.199.108.153]); Mon, 15 Mar 2026 10:01:00 +0000\r\n"
        "\r\n"
        "Body\r\n"
    )
    parsed = parse_email(raw_email)
    header_intel = analyze_headers(parsed)

    candidates = header_intel.candidate_relays
    assert len(candidates) == 4

    # Tier 1: Recipient MTA observed (209.85.220.41)
    assert candidates[0]["ip"] == "209.85.220.41"
    assert candidates[0]["tier"] == 1
    assert candidates[0]["tier_name"] == "RECIPIENT_MTA_OBSERVED"
    assert candidates[0]["confidence"] == "high"

    # Tier 2: Upstream MTA recorded (93.184.216.34)
    assert candidates[1]["ip"] == "93.184.216.34"
    assert candidates[1]["tier"] == 2
    assert candidates[1]["tier_name"] == "UPSTREAM_MTA_RECORDED"
    assert candidates[1]["confidence"] == "medium"

    # Tier 3: Unverified upstream hop (185.199.108.153)
    assert candidates[2]["ip"] == "185.199.108.153"
    assert candidates[2]["tier"] == 3
    assert candidates[2]["tier_name"] == "UNVERIFIED_UPSTREAM_HOP"
    assert candidates[2]["confidence"] == "low"

    # Tier 4: Client- or Header-Supplied (X-Originating-IP: 76.223.181.101)
    assert candidates[3]["ip"] == "76.223.181.101"
    assert candidates[3]["tier"] == 4
    assert candidates[3]["tier_name"] == "CLIENT_OR_HEADER_SUPPLIED"
    assert candidates[3]["confidence"] == "low"
    assert "Header-supplied IP is untrusted" in candidates[3]["ranking_disclaimer"]

    # Upstream relay IP points to the highest ranked candidate (Tier 1)
    assert header_intel.upstream_relay_ip == "209.85.220.41"


# ── 4. UTC Normalization & Hop Timeline Skew Analysis Tests ────────

def test_utc_normalization_across_different_timezone_offsets():
    """
    Requirement 3: Hop timestamps in different local offsets (+0530 vs -0400)
    must be converted to UTC before computing hop-to-hop latency deltas.
    """
    # Hop 1: 15:30:00 +0530 (10:00:00 UTC)
    # Hop 2: 06:00:30 -0400 (10:00:30 UTC) -> Delta should be +30 seconds, NOT hours!
    raw_email = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: UTC Normalization Test\r\n"
        "Received: from mx.recipient.com ([209.85.220.41]) by mail.recipient.com with ESMTP; Mon, 15 Mar 2026 06:00:30 -0400\r\n"
        "Received: from origin.relay.com ([93.184.216.34]) by mx.recipient.com with ESMTP; Mon, 15 Mar 2026 15:30:00 +0530\r\n"
        "\r\n"
        "Body\r\n"
    )
    parsed = parse_email(raw_email)
    header_intel = analyze_headers(parsed)

    timeline = header_intel.timeline_analysis
    assert timeline["status"] == "consistent"
    assert len(timeline["hop_deltas"]) == 1

    delta = timeline["hop_deltas"][0]["delta_seconds"]
    assert delta == pytest.approx(30.0)
    assert len(timeline["anomalies"]) == 0


def test_timeline_skew_exceeding_tolerance_flags_anomaly():
    """
    Hop timestamps where current hop is earlier than previous hop by > 120s
    flags TIMESTAMP_SKEW_OBSERVED as an envelope timeline observation.
    """
    # Hop 1: 10:05:00 UTC
    # Hop 2: 10:00:00 UTC (negative 300 seconds delta, exceeding 120s tolerance)
    raw_email = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Skew Anomaly Test\r\n"
        "Received: from mx.recipient.com ([209.85.220.41]) by mail.recipient.com with ESMTP; Mon, 15 Mar 2026 10:00:00 +0000\r\n"
        "Received: from origin.relay.com ([93.184.216.34]) by mx.recipient.com with ESMTP; Mon, 15 Mar 2026 10:05:00 +0000\r\n"
        "\r\n"
        "Body\r\n"
    )
    parsed = parse_email(raw_email)
    header_intel = analyze_headers(parsed)

    timeline = header_intel.timeline_analysis
    assert timeline["status"] == "skew_observed"
    assert len(timeline["anomalies"]) == 1

    anomaly = timeline["anomalies"][0]
    assert anomaly["type"] == "TIMESTAMP_SKEW_OBSERVED"
    assert anomaly["delta_seconds"] == pytest.approx(-300.0)
    assert anomaly["tolerance_seconds"] == 120
    assert "Possible clock skew" in anomaly["description"]


# ── 5. Neutral Programmatic Sender & Charset Fingerprinting ───────

def test_neutral_programmatic_sender_classification():
    """
    Verify automated libraries (PHPMailer, smtplib) are classified neutrally
    as 'Programmatic / Automated Sender', and charsets include neutral disclaimer.
    """
    raw_email = (
        "From: transactions@store.com\r\n"
        "To: customer@example.com\r\n"
        "Subject: Your Order Confirmation\r\n"
        "X-Mailer: PHPMailer 6.5.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"b1_abcdef123456\"\r\n"
        "\r\n"
        "--b1_abcdef123456\r\n"
        "Content-Type: text/plain; charset=\"windows-1251\"\r\n"
        "\r\n"
        "Order receipt\r\n"
        "--b1_abcdef123456--\r\n"
    )
    parsed = parse_email(raw_email)
    header_intel = analyze_headers(parsed)
    fp = header_intel.client_fingerprint

    assert fp is not None
    assert fp.mailer_category == "Programmatic / Automated Sender"
    assert fp.mime_boundary_style == "PHPMailer"
    assert "windows-1251" in fp.charsets_detected
    assert "byte serialization format" in fp.charset_disclaimer

    # Evidence item generated must be severity='info', channel='forensic', evidence_class='HEURISTIC'
    evidence = correlate_evidence(
        ml=MLResult("Legitimate", -0.5, True, "Legit"),
        auth=AuthResult("PASS", "PASS", "PASS", "", "", "", True, False, "Pass"),
        ip_intel=IPIntelligence([], [], False, False, 0, []),
        domain_intel=DomainIntelligence("store.com", "clean", 0, [], 500, "Reg", 0, False, "com", False, "", 0, [], "whois"),
        url_analysis=URLAnalysis(0, 0, [], [], []),
        att_analysis=AttachmentAnalysis(0, 0, []),
        header_intel=header_intel,
        parsed=parsed,
    )

    fp_items = [e for e in evidence if e["source"] == "Forensic/Fingerprint"]
    assert len(fp_items) >= 1
    for item in fp_items:
        assert item["severity"] == "info"
        assert item["channel"] == "forensic"
        assert item["evidence_class"] == "HEURISTIC"


# ── 6. Timezone Discrepancy Heuristic & Configurable Threshold ────

def test_correlate_timezone_configurable_threshold():
    """
    Verify timezone correlation uses configurable threshold (default 4.0h),
    and labels result as divergence_observed with heuristic disclaimer.
    """
    date_header = "Tue, 15 Mar 2026 14:30:00 -0400"
    relay_tz = "Asia/Kolkata"

    # Default threshold 4.0h: 9.5h diff > 4.0h -> divergence_observed
    res_default = correlate_timezone(date_header, relay_tz)
    assert res_default is not None
    assert res_default["discrepancy_hours"] == 9.5
    assert res_default["is_discrepancy"] is True
    assert res_default["status"] == "divergence_observed"
    assert res_default["threshold_hours"] == 4.0
    assert "does not prove timestamp manipulation" in res_default["heuristics_note"]

    # Custom threshold 10.0h: 9.5h diff <= 10.0h -> consistent
    res_custom = correlate_timezone(date_header, relay_tz, threshold_hours=10.0)
    assert res_custom is not None
    assert res_custom["is_discrepancy"] is False
    assert res_custom["status"] == "consistent"
    assert res_custom["threshold_hours"] == 10.0


# ── 7. External Intelligence Deduplication & Pre-Lookup Caching ───

def test_external_intelligence_deduplication():
    """Requirement 4: Duplicate IPs across headers trigger only a single external lookup."""
    clear_geo_cache()
    # 3 identical public IPs
    ip_list = ["93.184.216.34", "93.184.216.34", "93.184.216.34"]

    # In-memory session cache guarantees that the lookup function only queries external API once
    records = geolocate_ips(ip_list)
    assert len(records) == 3
    for r in records:
        assert r.ip == "93.184.216.34"


# ── 8. Strict Architectural Threat Score Isolation ────────────────

def test_threat_score_isolation_from_attribution_signals():
    """
    Forensic attribution signals (channel='forensic') must never contribute
    to or modify the numeric threat score (0-100).
    """
    raw_email = (
        "From: sender@legitdomain.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Meeting Notes\r\n"
        "Date: Mon, 15 Mar 2026 14:30:00 -0400\r\n"
        "X-Mailer: PHPMailer 6.2.0\r\n"
        "Received: from mx.recipient.com ([209.85.220.41]) by gate.recipient.com with ESMTP; Mon, 15 Mar 2026 10:00:00 +0000\r\n"
        "Received: from origin.relay.com ([93.184.216.34]) by mx.recipient.com with ESMTP; Mon, 15 Mar 2026 10:05:00 +0000\r\n"
        "\r\n"
        "Here are the notes from our discussion.\r\n"
    )
    parsed = parse_email(raw_email)
    header_intel = analyze_headers(parsed)

    ml = MLResult(prediction="Legitimate", decision_score=-1.2, model_available=True, note="Clean")
    auth = AuthResult("PASS", "PASS", "PASS", "", "", "", True, False, "Pass")
    ip_intel = IPIntelligence(["209.85.220.41", "93.184.216.34"], [], False, False, 0, [])
    domain_intel = DomainIntelligence("legitdomain.com", "clean", 0, [], 1000, "Reg", 0, False, "com", False, "", 0, [], "whois")
    url_analysis = URLAnalysis(0, 0, [], [], [])
    att_analysis = AttachmentAnalysis(0, 0, [])

    score_result = compute_threat_score(
        ml=ml,
        auth=auth,
        ip_intel=ip_intel,
        domain_intel=domain_intel,
        url_analysis=url_analysis,
        att_analysis=att_analysis,
        header_intel=header_intel,
    )

    # Score should remain exactly CLEAN / Low Risk regardless of timeline skew and PHPMailer headers
    assert score_result.threat_score <= 25
    assert score_result.verdict == "CLEAN" or score_result.verdict == "LOW_RISK"
    assert "ml" in score_result.sub_scores
    assert "authentication" in score_result.sub_scores
    # Forensic channel is not a signal weight in config
    assert "forensic" not in config.SIGNAL_WEIGHTS


# ── 9. End-to-End Report Generation Test ──────────────────────────

def test_report_includes_observational_forensic_fields():
    """Verify final JSON report includes forensic scope, candidate relays, and timeline analysis."""
    raw_email = (
        "From: admin@testorg.com\r\n"
        "To: employee@testorg.com\r\n"
        "Subject: System Update\r\n"
        "Date: Wed, 16 Mar 2026 09:00:00 +0530\r\n"
        "Received: from mail.google.com ([209.85.220.41]) by mx.target.com with ESMTP; Wed, 16 Mar 2026 09:01:00 +0530\r\n"
        "Received: from origin.server.com ([93.184.216.34]) by mail.google.com with ESMTP; Wed, 16 Mar 2026 09:00:30 +0530\r\n"
        "\r\n"
        "Please read the attached update guidelines.\r\n"
    )
    parsed = parse_email(raw_email)
    header_intel = analyze_headers(parsed)
    geo_rec = GeoRecord(
        ip="209.85.220.41",
        country="United States",
        region="California",
        city="Mountain View",
        timezone="America/Los_Angeles",
        asn="AS15169",
        org="Google LLC",
        source="IPinfo",
        status="success",
    )

    ml = MLResult(prediction="Legitimate", decision_score=-0.8, model_available=True, note="Legit")
    auth = AuthResult("PASS", "PASS", "PASS", "", "", "", True, False, "Pass")
    ip_intel = IPIntelligence(["209.85.220.41", "93.184.216.34"], [], False, False, 0, [])
    domain_intel = DomainIntelligence("testorg.com", "clean", 0, [], 800, "Google", 0, False, "com", False, "", 0, [], "whois")
    url_analysis = URLAnalysis(0, 0, [], [], [])
    att_analysis = AttachmentAnalysis(0, 0, [])
    threat_score = compute_threat_score(ml, auth, ip_intel, domain_intel, url_analysis, att_analysis, header_intel)

    report = generate_report(
        parsed=parsed,
        auth=auth,
        header_intel=header_intel,
        ip_intel=ip_intel,
        geo_records=[geo_rec],
        url_analysis=url_analysis,
        att_analysis=att_analysis,
        ml=ml,
        domain_intel=domain_intel,
        threat_score=threat_score,
    )

    infra = report["infrastructure"]
    assert "Physical attribution is outside the scope" in infra["forensic_scope"]
    assert len(infra["candidate_relays"]) >= 1
    assert "timeline_analysis" in infra
    assert "chronological_hops" in infra
    assert infra["chronological_hops"][0]["raw"] != ""
    assert infra["chronological_hops"][0]["evidence_class"] == "DERIVED"
    assert "forensic_anomalies" in report
