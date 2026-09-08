"""
GmailGuard — Pipeline Orchestrator

Single public API:
    analyze_email(raw_email: str) -> dict

Runs each analysis module in order and assembles the final report.
Designed to be called directly by FastAPI endpoints later.

CLI usage:
    python main.py path/to/email.eml
    python main.py path/to/email.eml --pretty
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

if __name__ == "__main__" and not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "backend"

# ── Analysis modules ─────────────────────────────────────────────
from .email_parser import parse_email
from .header_analyzer import analyze_headers
from .authentication_analyzer import analyze_authentication
from .ip_intelligence import analyze_ips
from .geolocation import geolocate_ips
from .url_analyzer import analyze_urls
from .attachment_analyzer import analyze_attachments
from .ml_classifier import classify_email
from .domain_intelligence import analyze_domain
from .forensic_domain_intelligence import run_forensic_domain_analysis
from .ioc_extractor import extract_iocs
from .osint_intelligence import run_osint_analysis
from .evidence_correlator import correlate_evidence
from .phish_tank import check_urls_phishtank
from .threat_scorer import compute_threat_score
from .report_generator import generate_report


def analyze_email(raw_email: str) -> dict[str, Any]:
    """
    Analyze a raw RFC 5322 email string and return a structured
    forensic threat report.

    This is the single entry point for:
      - CLI usage
      - FastAPI endpoint (pass raw_email from request body)
      - Unit testing

    Args:
        raw_email: The full raw email as a string.

    Returns:
        A JSON-serializable dict with threat score, verdict, and
        evidence from all analysis signals.
    """

    # ── Step 1: Parse email ──────────────────────────────────────
    parsed = parse_email(raw_email)

    # ── Step 2: Header / infrastructure analysis ─────────────────
    header_intel = analyze_headers(parsed)

    # ── Step 3: Authentication (SPF / DKIM / DMARC) ──────────────
    auth = analyze_authentication(parsed)

    # ── Step 4: IP intelligence ──────────────────────────────────
    ip_intel = analyze_ips(parsed)

    # ── Step 5: Geolocation (forensic context only) ───────────────
    geo_records = geolocate_ips(ip_intel.public_ips)

    # ── Step 6: URL analysis ─────────────────────────────────────
    url_analysis = analyze_urls(parsed.text_body, parsed.html_body)

    # ── Step 7: Attachment analysis ───────────────────────────────
    att_analysis = analyze_attachments(parsed.attachments)

    # ── Step 8: ML / NLP classification ──────────────────────────
    ml_result = classify_email(parsed.text_body, parsed.html_body)

    # ── Step 9: Domain intelligence ──────────────────────────────
    domain_intel = analyze_domain(parsed.sender_domain)

    # ── Step 10: Threat scoring ───────────────────────────────────
    threat_score = compute_threat_score(
        ml=ml_result,
        auth=auth,
        ip_intel=ip_intel,
        domain_intel=domain_intel,
        url_analysis=url_analysis,
        att_analysis=att_analysis,
        header_intel=header_intel,
    )

    # ── Step 10.5: Forensic domain intelligence ───────────────────
    # Investigates historical DNS, IPs, WHOIS, and security detections
    # for the sender domain + all URL domains. Purely additive — does
    # not affect the threat score unless FORENSIC_HISTORY_SCORE_WEIGHT > 0.
    forensic_result = run_forensic_domain_analysis(parsed, url_analysis)

    # ── Step 10.6: OSINT intelligence ──────────────────────────────
    # Passive public intelligence lookup on deduplicated indicators
    # (domains, IPs, URLs).
    ioc_bundle = extract_iocs(parsed, url_analysis=url_analysis, ip_intel=ip_intel)
    osint_result = run_osint_analysis(ioc_bundle)

    # ── Step 10.7: PhishTank URL intelligence ─────────────────────
    # Check extracted URLs against the PhishTank known-phishing database.
    phishtank_result = check_urls_phishtank(ioc_bundle.urls)

    # ── Step 10.8: Evidence correlation ───────────────────────────
    correlated_evidence = correlate_evidence(
        ml=ml_result,
        auth=auth,
        ip_intel=ip_intel,
        domain_intel=domain_intel,
        url_analysis=url_analysis,
        att_analysis=att_analysis,
        osint_result=osint_result,
        forensic_result=forensic_result,
        phishtank_result=phishtank_result,
        geo_records=geo_records,
        header_intel=header_intel,
        parsed=parsed,
    )

    # ── Step 11: Generate report ──────────────────────────────────
    report = generate_report(
        parsed=parsed,
        auth=auth,
        header_intel=header_intel,
        ip_intel=ip_intel,
        geo_records=geo_records,
        url_analysis=url_analysis,
        att_analysis=att_analysis,
        ml=ml_result,
        domain_intel=domain_intel,
        threat_score=threat_score,
        forensic_result=forensic_result,
        osint_result=osint_result,
        correlated_evidence=correlated_evidence,
        phishtank_result=phishtank_result,
    )

    return report


# ── CLI entry point ───────────────────────────────────────────────

def _print_summary(report: dict) -> None:
    """Print a human-readable summary to stdout."""
    print("\n" + "=" * 60)
    print(f"  GmailGuard Threat Report")
    print("=" * 60)
    print(f"  Threat Score : {report['threat_score']}/100")
    print(f"  Verdict      : {report['verdict']}")
    print(f"  From         : {report['email']['from']}")
    print(f"  Subject      : {report['email']['subject']}")
    print(f"  SPF          : {report['authentication']['spf']}")
    print(f"  DKIM         : {report['authentication']['dkim']}")
    print(f"  DMARC        : {report['authentication']['dmarc']}")
    print(f"  ML Prediction: {report['ml']['prediction']}")
    print(f"  URLs         : {report['urls']['count']} total, {report['urls']['suspicious']} suspicious")
    print(f"  Attachments  : {report['attachments']['count']} total, {report['attachments']['suspicious']} suspicious")

    if report["evidence"]:
        print("\n  ⚠  Risk Factors:")
        for ev in report["evidence"]:
            print(f"     [{ev['impact']}] {ev['signal']}: {ev['explanation'][:100]}")

    if report["positive_evidence"]:
        print("\n  ✓  Positive Signals:")
        for ev in report["positive_evidence"]:
            print(f"     {ev['signal']}: {ev['explanation'][:100]}")

    if report.get("correlated_evidence"):
        print("\n  🔍  Correlated Forensic Evidence:")
        for cev in report["correlated_evidence"][:5]:
            print(f"     [{cev['source']}] {cev['finding'][:110]}")

    infra = report.get("infrastructure", {})
    upstream_ip = infra.get("upstream_relay_ip")
    if upstream_ip:
        print(f"\n  🚀  Primary Candidate Relay : {upstream_ip}")
    candidates = infra.get("candidate_relays", [])
    if candidates:
        print(f"  📌  Candidate Relays       : {len(candidates)} ranked public hop(s)")
        for cand in candidates[:3]:
            print(f"      - {cand['ip']} [Tier {cand['tier']}: {cand['tier_name']}] (conf: {cand['confidence']})")
    timeline = infra.get("timeline_analysis", {})
    if timeline:
        tl_status = timeline.get("status", "unknown")
        if tl_status == "skew_observed":
            print(f"  ⏱️  Timeline Analysis       : ⚠️ SKEW OBSERVED ({len(timeline.get('anomalies', []))} anomalies)")
        elif tl_status == "consistent":
            print(f"  ⏱️  Timeline Analysis       : ✅ CONSISTENT ({len(timeline.get('hop_deltas', []))} hops analyzed)")
    fp = infra.get("client_fingerprint")
    if fp:
        print(f"  🔍  Client Fingerprint      : {fp.get('fingerprint_summary', 'Standard')}")
    tz_corr = infra.get("timezone_correlation")
    if tz_corr:
        tz_status = "⚠️  DIVERGENCE OBSERVED" if tz_corr.get("is_discrepancy") else "✅  CONSISTENT"
        print(f"  🕒  Timezone Analysis       : {tz_status} (Date: {tz_corr.get('stated_offset')}, Relay: {tz_corr.get('relay_timezone')} {tz_corr.get('relay_offset')}, diff: {tz_corr.get('discrepancy_hours')}h, thresh: {tz_corr.get('threshold_hours', 4.0)}h)")

    geos = infra.get("geolocation", [])
    if geos:
        print("\n  🌍  Observable Infrastructure (IPinfo):")
        for g in geos[:3]:
            ip = g.get("ip", "UNKNOWN")
            country = g.get("country", "UNKNOWN")
            region = g.get("region", "UNKNOWN")
            city = g.get("city", "UNKNOWN")
            asn = g.get("asn", "UNKNOWN")
            org = g.get("organization") or g.get("org", "UNKNOWN")
            source = g.get("source", "IPinfo")
            print(f"     IP          : {ip}")
            print(f"     Country     : {country}")
            print(f"     Region      : {region}")
            print(f"     City        : {city}")
            print(f"     ASN         : {asn}")
            print(f"     Organization: {org}")
            print(f"     Source      : {source}")
            print("     Note        : Approximate IP-based infrastructure location, not sender's physical location.")

    forensics = report.get("forensics", {})
    osint = forensics.get("osint")
    if osint:
        total_ioc = len(osint.get("domains", [])) + len(osint.get("ips", [])) + len(osint.get("urls", []))
        print(f"\n  🌐  OSINT Intelligence ({osint.get('data_source', 'Passive')}):")
        print(f"     Investigated: {len(osint.get('domains', []))} domain(s), {len(osint.get('ips', []))} IP(s), {len(osint.get('urls', []))} URL(s)")

    if report["limitations"]:
        print("\n  ℹ  Limitations:")
        for lim in report["limitations"][:5]:
            print(f"     • {lim[:100]}")

    print("=" * 60 + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="GmailGuard — Email Threat Analysis Engine"
    )
    parser.add_argument("email_file", help="Path to .eml file to analyze")
    parser.add_argument("--json", action="store_true", help="Output full JSON report")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parser.add_argument("--output", "-o", help="Write JSON output to this file")
    args = parser.parse_args()

    eml_path = Path(args.email_file)
    if not eml_path.exists():
        print(f"Error: File not found: {eml_path}", file=sys.stderr)
        sys.exit(1)

    raw = eml_path.read_text(encoding="utf-8", errors="replace")

    # Run pipeline
    result = analyze_email(raw)

    # Output
    if args.output:
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Report written to: {out_path}")
    elif args.json or args.pretty:
        indent = 2 if args.pretty else None
        print(json.dumps(result, indent=indent, ensure_ascii=False))
    else:
        _print_summary(result)
        print("Tip: run with --pretty for full JSON report.\n")


def __getattr__(name: str):
    """Allow uvicorn main:app to seamlessly load the FastAPI app from api.py."""
    if name == "app":
        from .api import app
        return app
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
