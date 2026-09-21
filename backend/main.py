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
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger("gmailguard.pipeline")

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
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import time as _time

    _t0 = _time.monotonic()

    # ── Phase 1: Sequential — Parse email (everything depends on this) ──
    parsed = parse_email(raw_email)

    # ── Phase 2: Sequential — Fast local analysis (<1ms each) ───────────
    header_intel = analyze_headers(parsed)
    auth = analyze_authentication(parsed)
    ip_intel = analyze_ips(parsed)
    att_analysis = analyze_attachments(parsed.attachments)
    att_content_analysis = analyze_attachment_contents(parsed.attachments)
    att_extracted_urls = att_content_analysis.get_all_urls()
    url_analysis = analyze_urls(
        parsed.text_body,
        parsed.html_body,
        additional_urls=att_extracted_urls,
    )
    att_content_analysis.attach_url_intelligence(url_analysis.findings)
    ml_result = classify_email(parsed.text_body, parsed.html_body, parsed.subject)
    domain_intel = analyze_domain(parsed.sender_domain)
    ioc_bundle = extract_iocs(parsed, url_analysis=url_analysis, ip_intel=ip_intel)

    _t1 = _time.monotonic()
    logger.info("Phase 1+2 (local analysis) completed in %.2fs", _t1 - _t0)

    # ── Phase 3: PARALLEL — All independent network I/O ─────────────────
    # These modules don't depend on each other, so run them concurrently.
    # This turns sum(geo + phishtank + sandbox + forensic + osint) into
    # max(geo, phishtank, sandbox, forensic, osint).
    geo_records = None
    phishtank_result = None
    url_sandbox = None
    forensic_result = None
    osint_result = None

    def _run_geolocation():
        return geolocate_ips(ip_intel.public_ips)

    def _run_phishtank():
        return check_urls_phishtank(ioc_bundle.urls)

    def _run_url_sandbox():
        return analyze_urls_dynamic(ioc_bundle.urls)

    def _run_forensic_domain():
        return run_forensic_domain_analysis(parsed, url_analysis)

    def _run_osint():
        return run_osint_analysis(ioc_bundle)

    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="gmailguard-io") as executor:
        futures = {
            executor.submit(_run_geolocation): "geolocation",
            executor.submit(_run_phishtank): "phishtank",
            executor.submit(_run_url_sandbox): "url_sandbox",
            executor.submit(_run_forensic_domain): "forensic_domain",
            executor.submit(_run_osint): "osint",
        }

        for future in as_completed(futures):
            task_name = futures[future]
            try:
                result = future.result()
                if task_name == "geolocation":
                    geo_records = result
                elif task_name == "phishtank":
                    phishtank_result = result
                elif task_name == "url_sandbox":
                    url_sandbox = result
                elif task_name == "forensic_domain":
                    forensic_result = result
                elif task_name == "osint":
                    osint_result = result
                logger.info("Parallel task '%s' completed", task_name)
            except Exception as exc:
                logger.error("Parallel task '%s' failed: %s", task_name, exc)

    _t2 = _time.monotonic()
    logger.info("Phase 3 (parallel network I/O) completed in %.2fs", _t2 - _t1)

    # Ensure fallbacks if any task failed
    if geo_records is None:
        geo_records = []
    if phishtank_result is None:
        phishtank_result = check_urls_phishtank([])
    if url_sandbox is None:
        from .url_sandbox import URLSandboxAnalysis
        url_sandbox = URLSandboxAnalysis()
    if forensic_result is None:
        from .forensic_domain_intelligence import ForensicIntelligenceResult
        forensic_result = ForensicIntelligenceResult()
    if osint_result is None:
        from .osint_intelligence import run_osint_analysis as _fallback_osint
        from .ioc_extractor import IOCBundle
        osint_result = _fallback_osint(IOCBundle())

    # ── Phase 4: Sequential — Scoring & correlation (depends on Phase 3) ─
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

    _t3 = _time.monotonic()
    logger.info("Phase 4 (scoring + report) completed in %.2fs | TOTAL: %.2fs", _t3 - _t2, _t3 - _t0)

    # ── Phase 5: Gemini AI Contextual Security Reasoning ───────────────
    try:
        from .gemini_security import analyze_email_security
        gemini_result = analyze_email_security(raw_email=raw_email, report=report)
        report["gemini_analysis"] = gemini_result
        report["ai_analysis"] = gemini_result
    except Exception as gemini_err:
        logger.warning("Gemini AI security analysis error: %s", gemini_err)
        from .gemini_security import _build_fallback_response
        fallback_ai = _build_fallback_response(
            pipeline_score=report.get("threat_score", 0),
            pipeline_verdict=report.get("verdict", "UNKNOWN"),
            reason=str(gemini_err),
        )
        report["gemini_analysis"] = fallback_ai
        report["ai_analysis"] = fallback_ai

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
        print(f"\n  🛡️  Local Browserless Sandbox : {url_sandbox_info['total_scanned']} URL(s) dynamically evaluated")
        print(f"      Malicious: {url_sandbox_info.get('malicious_count', 0)} | Suspicious: {url_sandbox_info.get('suspicious_count', 0)}")
        for f in url_sandbox_info.get("findings", [])[:3]:
            print(f"      - [{f.get('verdict')}] {f.get('submitted_url')} (score: {f.get('malicious_score')}/100)")
            if f.get("screenshot_url"):
                print(f"        Screenshot: {f.get('screenshot_url')}")

    gemini = report.get("gemini_analysis", {})
    if gemini and gemini.get("available"):
        print(f"\n  🤖  Gemini AI Threat Reasoning ({gemini.get('model_used', 'Gemini Flash')}):")
        print(f"      Classification : {gemini.get('classification', '').upper()} (Confidence: {gemini.get('confidence')}%)")
        print(f"      Risk Level     : {gemini.get('risk_level', '').upper()}")
        print(f"      Executive Summary: {gemini.get('summary')}")
        if gemini.get("threat_indicators"):
            print(f"      Key Indicators:")
            for ti in gemini.get("threat_indicators", [])[:3]:
                print(f"        • [{ti.get('severity', 'info').upper()}] {ti.get('indicator')}: {ti.get('evidence')}")
        if gemini.get("recommended_actions"):
            print(f"      Recommended Actions:")
            for act in gemini.get("recommended_actions", [])[:2]:
                print(f"        ✓ {act}")

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
