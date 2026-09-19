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
from .attachment_content_analyzer import analyze_attachment_contents
from .ml_classifier import classify_email
from .domain_intelligence import analyze_domain
from .forensic_domain_intelligence import run_forensic_domain_analysis
from .ioc_extractor import extract_iocs
from .osint_intelligence import run_osint_analysis
from .evidence_correlator import correlate_evidence
from .phish_tank import check_urls_phishtank
from .url_sandbox import analyze_urls_dynamic
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

    # ── Step 7: Attachment static analysis ───────────────────────
    att_analysis = analyze_attachments(parsed.attachments)

    # ── Step 7.5: Deep Attachment Content Analysis ───────────────
    # Safely inspects the internal contents of documents (PDF, text, archives).
    # Extracts text, links, actions, forms, JavaScript, embedded files, and metadata.
    # Detects password-protection / encryption without attempting bypass.
    att_content_analysis = analyze_attachment_contents(parsed.attachments)
    att_extracted_urls = att_content_analysis.get_all_urls()

    # ── Step 6: URL analysis ─────────────────────────────────────
    # Combines URLs from email body text, HTML, and attachments so all links
    # enter the exact same reputation and intelligence pipeline without duplication.
    url_analysis = analyze_urls(
        parsed.text_body,
        parsed.html_body,
        additional_urls=att_extracted_urls,
    )

    # Attach correlated URL reputation back into the attachment findings
    att_content_analysis.attach_url_intelligence(url_analysis.findings)

    # ── Step 8: ML / NLP classification ──────────────────────────
    ml_result = classify_email(parsed.text_body, parsed.html_body)

    # ── Step 9: Domain intelligence ──────────────────────────────
    domain_intel = analyze_domain(parsed.sender_domain)

    # ── Step 9.5: Observable IOC Extraction ──────────────────────
    ioc_bundle = extract_iocs(parsed, url_analysis=url_analysis, ip_intel=ip_intel)

    # ── Step 9.6: PhishTank URL intelligence ─────────────────────
    phishtank_result = check_urls_phishtank(ioc_bundle.urls)

    # ── Step 9.7: urlscan.io Dynamic URL Sandbox ────────────────
    # Safely executes URLs in the remote isolated urlscan.io cloud sandbox.
    # URLs are NEVER opened locally.
    url_sandbox = analyze_urls_dynamic(ioc_bundle.urls)

    # ── Step 10: Threat scoring ───────────────────────────────────
    threat_score = compute_threat_score(
        ml=ml_result,
        auth=auth,
        ip_intel=ip_intel,
        domain_intel=domain_intel,
        url_analysis=url_analysis,
        att_analysis=att_analysis,
        header_intel=header_intel,
        att_content_analysis=att_content_analysis,
        url_sandbox=url_sandbox,
        geo_records=geo_records,
    )

    # ── Step 10.5: Forensic domain intelligence ───────────────────
    # Investigates historical DNS, IPs, WHOIS, and security detections
    # for the sender domain + all URL domains. Purely additive — does
    # not affect the threat score unless FORENSIC_HISTORY_SCORE_WEIGHT > 0.
    forensic_result = run_forensic_domain_analysis(parsed, url_analysis)

    # ── Step 10.6: OSINT intelligence ──────────────────────────────
    # Passive public intelligence lookup on deduplicated indicators
    # (domains, IPs, URLs).
    osint_result = run_osint_analysis(ioc_bundle)

    # ── Safe Pipeline Diagnostics ─────────────────────────────────
    try:
        url_found_count = len(parsed.urls) + len(att_extracted_urls)
        url_unique_count = len(url_analysis.all_urls)
        sb_mode = getattr(url_sandbox, "mode", "LIVE")
        sb_submitted = getattr(url_sandbox, "total_scanned", 0)
        sb_completed = sum(1 for f in getattr(url_sandbox, "findings", []) if f.status == "COMPLETED")
        sb_failed = sum(1 for f in getattr(url_sandbox, "findings", []) if f.status in ("ERROR", "TIMEOUT", "FAILED"))
        ip_public_count = len(ip_intel.public_ips)
        ip_lookups = len(geo_records)
        ip_success = sum(1 for g in geo_records if getattr(g, "status", "") == "success")
        ip_not_found = sum(1 for g in geo_records if getattr(g, "status", "") == "not_found")
        ip_errors = sum(1 for g in geo_records if getattr(g, "status", "") in ("error", "unavailable"))
        url_ev_count = len([e for e in threat_score.evidence if "URL" in e.signal])
        ip_ev_count = len([e for e in threat_score.evidence if "IP" in e.signal or "Infrastructure" in e.signal])
        att_ev_count = len([e for e in threat_score.evidence if "Attachment" in e.signal])

        logger.info(
            "--- GmailGuard Safe Diagnostics ---\n"
            "URL extraction:\n"
            "  %d URLs found\n"
            "  %d unique URLs\n"
            "URL sandbox:\n"
            "  MODE: %s\n"
            "  %d URLs submitted\n"
            "  %d completed\n"
            "  %d failed\n"
            "IP intelligence:\n"
            "  %d public IPs detected\n"
            "  %d IPinfo lookups attempted\n"
            "  %d successful\n"
            "  %d not found\n"
            "  %d errors\n"
            "Correlation:\n"
            "  %d URL evidence count\n"
            "  %d IP evidence count\n"
            "  %d attachment evidence count\n"
            "  ML result: %s\n"
            "  Final score: %d\n"
            "  Final verdict: %s",
            url_found_count, url_unique_count,
            sb_mode, sb_submitted, sb_completed, sb_failed,
            ip_public_count, ip_lookups, ip_success, ip_not_found, ip_errors,
            url_ev_count, ip_ev_count, att_ev_count, ml_result.prediction,
            threat_score.threat_score, threat_score.verdict,
        )
    except Exception:
        pass

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
        att_content_analysis=att_content_analysis,
        url_sandbox=url_sandbox,
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
        att_content_analysis=att_content_analysis,
        url_sandbox=url_sandbox,
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

    url_sandbox_info = forensics.get("url_sandbox")
    if url_sandbox_info and url_sandbox_info.get("total_scanned", 0) > 0:
        print(f"\n  🛡️  urlscan.io Cloud Sandbox : {url_sandbox_info['total_scanned']} URL(s) dynamically evaluated")
        print(f"      Malicious: {url_sandbox_info.get('malicious_count', 0)} | Suspicious: {url_sandbox_info.get('suspicious_count', 0)}")
        for f in url_sandbox_info.get("findings", [])[:3]:
            print(f"      - [{f.get('verdict')}] {f.get('submitted_url')} (score: {f.get('malicious_score')}/100)")
            if f.get("screenshot_url"):
                print(f"        Screenshot: {f.get('screenshot_url')}")

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
