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

# ── Analysis modules ─────────────────────────────────────────────
from email_parser          import parse_email
from header_analyzer       import analyze_headers
from authentication_analyzer import analyze_authentication
from ip_intelligence       import analyze_ips
from geolocation           import geolocate_ips
from url_analyzer          import analyze_urls
from attachment_analyzer   import analyze_attachments
from ml_classifier         import classify_email
from domain_intelligence   import analyze_domain
from threat_scorer         import compute_threat_score
from report_generator      import generate_report


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
