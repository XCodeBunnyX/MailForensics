"""
GmailGuard — Evidence Correlation Engine

Combines signals across all detection vectors:
- ML / NLP content analysis
- Email authentication (SPF / DKIM / DMARC)
- IP intelligence & observable mail infrastructure
- Domain intelligence (typosquatting, age, TLD risk)
- URL analysis (obfuscation, shorteners, mismatches)
- Attachment analysis (macro-enabled, executables)
- OSINT intelligence (domain observations, IP context, URL detections)
- Historical infrastructure churn (DNS/IP changes over time)

Produces a structured, explainable 'correlated_evidence' list with clear
source attribution and cross-vector correlation synthesis.
"""

from __future__ import annotations

import email.utils
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from dataclasses import dataclass, field
from typing import Any, Optional

from .ml_classifier import MLResult
from .authentication_analyzer import AuthResult
from .ip_intelligence import IPIntelligence
from .domain_intelligence import DomainIntelligence
from .url_analyzer import URLAnalysis
from .attachment_analyzer import AttachmentAnalysis
from .osint_intelligence import OSINTAnalysisResult
from .forensic_domain_intelligence import ForensicIntelligenceResult
from . import config


@dataclass
class CorrelatedEvidenceItem:
    """A single piece of correlated evidence with source attribution."""
    source: str           # "ML", "Authentication", "URL", "IP", "Domain", "OSINT", "Cross-Vector", "Forensic/..."
    finding: str          # Clear factual explanation
    severity: str         # "info", "low", "medium", "high", "critical"
    details: dict[str, Any] = field(default_factory=dict)
    channel: str = "security"          # "security" vs "forensic"
    evidence_class: str = "DERIVED"    # "OBSERVED", "DERIVED", "HEURISTIC", "EXTERNAL_INTELLIGENCE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "finding": self.finding,
            "severity": self.severity,
            "details": self.details,
            "channel": self.channel,
            "evidence_class": self.evidence_class,
        }


def correlate_timezone(
    date_str: str,
    relay_timezone_str: str,
    threshold_hours: Optional[float] = None,
) -> Optional[dict[str, Any]]:
    """
    Compare stated Date header timezone against relay's geographic timezone from IPinfo.
    Returns structured analysis dict or None if insufficient data.
    """
    if not date_str or not relay_timezone_str:
        return None

    if threshold_hours is None:
        threshold_hours = getattr(config, "TIMEZONE_OBSERVATIONAL_DELTA_THRESHOLD_HOURS", 4.0)

    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            return None
        stated_offset_sec = dt.utcoffset().total_seconds()
        stated_offset_hrs = stated_offset_sec / 3600.0

        tz = ZoneInfo(relay_timezone_str)
        relay_dt = dt.astimezone(tz)
        relay_offset_sec = relay_dt.utcoffset().total_seconds()
        relay_offset_hrs = relay_offset_sec / 3600.0

        diff_hrs = abs(stated_offset_hrs - relay_offset_hrs)

        stated_sign = "+" if stated_offset_sec >= 0 else "-"
        stated_s = int(abs(stated_offset_sec))
        stated_str = f"{stated_sign}{stated_s // 3600:02d}:{(stated_s % 3600) // 60:02d}"

        relay_sign = "+" if relay_offset_sec >= 0 else "-"
        relay_s = int(abs(relay_offset_sec))
        relay_str = f"{relay_sign}{relay_s // 3600:02d}:{(relay_s % 3600) // 60:02d}"

        is_discrepancy = diff_hrs > threshold_hours
        return {
            "stated_offset": stated_str,
            "stated_offset_hours": stated_offset_hrs,
            "relay_timezone": relay_timezone_str,
            "relay_offset": relay_str,
            "relay_offset_hours": relay_offset_hrs,
            "discrepancy_hours": round(diff_hrs, 2),
            "is_discrepancy": is_discrepancy,
            "status": "divergence_observed" if is_discrepancy else "consistent",
            "threshold_hours": threshold_hours,
            "evidence_class": "HEURISTIC",
            "heuristics_note": (
                "A timezone discrepancy reflects differing configuration or geographic relaying; "
                "it does not prove timestamp manipulation or physical sender location."
            ),
        }
    except Exception:
        return None


def correlate_evidence(
    ml: MLResult,
    auth: AuthResult,
    ip_intel: IPIntelligence,
    domain_intel: DomainIntelligence,
    url_analysis: URLAnalysis,
    att_analysis: AttachmentAnalysis,
    osint_result: Optional[OSINTAnalysisResult] = None,
    forensic_result: Optional[ForensicIntelligenceResult] = None,
    phishtank_result: Optional[Any] = None,
    geo_records: Optional[list[Any]] = None,
    header_intel: Optional[Any] = None,
    parsed: Optional[Any] = None,
    att_content_analysis: Optional[Any] = None,
    url_sandbox: Optional[Any] = None,
) -> list[dict[str, Any]]:
    """
    Correlate findings across ML, Authentication, URLs, Infrastructure, OSINT, PhishTank, and urlscan.io Sandbox.
    Returns a list of dicts suitable for the final report.
    """
    evidence: list[CorrelatedEvidenceItem] = []

    # ── 1. ML Signal ──────────────────────────────────────────────
    is_ml_phish = ml.prediction.upper() == "PHISHING"
    if is_ml_phish:
        score_str = f" (decision score: {ml.decision_score:.2f})" if ml.decision_score is not None else ""
        evidence.append(CorrelatedEvidenceItem(
            source="ML",
            finding=f"Email content matches phishing linguistic patterns{score_str}.",
            severity="high" if (ml.decision_score is not None and ml.decision_score >= 1.0) else "medium",
            details={"prediction": ml.prediction, "decision_score": ml.decision_score},
        ))
    elif ml.prediction.upper() == "LEGITIMATE":
        evidence.append(CorrelatedEvidenceItem(
            source="ML",
            finding="Email content exhibits legitimate conversational characteristics.",
            severity="low",
            details={"prediction": ml.prediction, "decision_score": ml.decision_score},
        ))

    # ── 2. Authentication Signal ──────────────────────────────────
    auth_failed = (auth.spf == "FAIL" or auth.dmarc == "FAIL" or auth.dkim == "FAIL")
    auth_passed = (auth.spf == "PASS" and auth.dkim == "PASS")
    if auth_failed:
        reasons = []
        if auth.spf == "FAIL":
            reasons.append("SPF FAIL")
        if auth.dkim == "FAIL":
            reasons.append("DKIM FAIL")
        if auth.dmarc == "FAIL":
            reasons.append("DMARC FAIL")
        evidence.append(CorrelatedEvidenceItem(
            source="Authentication",
            finding=f"Email sender authentication failed ({', '.join(reasons)}), indicating potential sender spoofing.",
            severity="high",
            details={"spf": auth.spf, "dkim": auth.dkim, "dmarc": auth.dmarc},
        ))
    elif auth_passed:
        evidence.append(CorrelatedEvidenceItem(
            source="Authentication",
            finding="Sender domain passed cryptographic authentication (SPF and DKIM verified).",
            severity="info",
            details={"spf": auth.spf, "dkim": auth.dkim, "dmarc": auth.dmarc},
        ))

    # ── 3. URL Analysis Signal ────────────────────────────────────
    has_suspicious_url = url_analysis.suspicious_count > 0
    if has_suspicious_url:
        evidence.append(CorrelatedEvidenceItem(
            source="URL",
            finding=f"Detected {url_analysis.suspicious_count} suspicious URL(s) exhibiting obfuscation, shorteners, or structural anomalies.",
            severity="high" if url_analysis.suspicious_count >= 2 else "medium",
            details={"suspicious_count": url_analysis.suspicious_count, "total": url_analysis.total_count},
        ))

    # ── 4. IP Intelligence Signal ─────────────────────────────────
    has_bad_ip = any(r.reputation == "suspicious" for r in ip_intel.records)
    if has_bad_ip:
        evidence.append(CorrelatedEvidenceItem(
            source="IP",
            finding="Observed sending infrastructure IP address is associated with suspicious network reputation.",
            severity="medium",
            details={"records_count": len(ip_intel.records)},
        ))

    # ── 4b. Geolocation / Observable Infrastructure (IPinfo) ──────
    if geo_records:
        for g in geo_records:
            g_status = getattr(g, "status", "success")
            g_country = getattr(g, "country", "UNKNOWN")
            g_city = getattr(g, "city", "UNKNOWN")
            g_region = getattr(g, "region", "UNKNOWN")
            g_asn = getattr(g, "asn", "UNKNOWN")
            g_org = getattr(g, "organization", None) or getattr(g, "org", "UNKNOWN")
            g_ip = getattr(g, "ip", "")

            if g_status == "success" and (g_country != "UNKNOWN" or g_city != "UNKNOWN"):
                loc_parts = [p for p in [g_city, g_region, g_country] if p and p != "UNKNOWN"]
                loc_str = ", ".join(loc_parts) if loc_parts else "an approximate location"
                asn_org_parts = []
                if g_asn and g_asn != "UNKNOWN":
                    asn_org_parts.append(f"ASN: {g_asn}")
                if g_org and g_org != "UNKNOWN":
                    asn_org_parts.append(f"Org: {g_org}")
                asn_org_str = f" ({', '.join(asn_org_parts)})" if asn_org_parts else ""

                evidence.append(CorrelatedEvidenceItem(
                    source="IPinfo",
                    finding=(
                        f"Observed mail infrastructure ({g_ip}) is geolocated to {loc_str}{asn_org_str}. "
                        "Note: Approximate infrastructure location only, not sender's physical location."
                    ),
                    severity="info",
                    details={
                        "ip": g_ip,
                        "country": g_country,
                        "region": g_region,
                        "city": g_city,
                        "asn": g_asn,
                        "organization": g_org,
                        "location_type": "observable_infrastructure",
                    },
                ))
            elif g_status in ("error", "unavailable"):
                reason = getattr(g, "reason", "service unavailable")
                evidence.append(CorrelatedEvidenceItem(
                    source="IPinfo",
                    finding=f"IPinfo observable infrastructure lookup for {g_ip} encountered limitation ({reason}).",
                    severity="info",
                    details={"ip": g_ip, "status": "ERROR", "reason": reason},
                ))
            elif g_status == "not_found":
                evidence.append(CorrelatedEvidenceItem(
                    source="IPinfo",
                    finding=f"IPinfo observable infrastructure lookup for {g_ip}: no intelligence returned.",
                    severity="info",
                    details={"ip": g_ip, "status": "NOT_FOUND"},
                ))

    # ── 4c. Timezone Discrepancy Heuristic ────────────────────────
    if parsed and getattr(parsed, "date", None) and geo_records:
        date_str = parsed.date
        # Pick the first geo_record with a valid timezone
        relay_tz = None
        target_geo = None
        for g in geo_records:
            tz_val = getattr(g, "timezone", None)
            if tz_val and tz_val != "UNKNOWN":
                relay_tz = tz_val
                target_geo = g
                break

        if relay_tz:
            tz_res = correlate_timezone(date_str, relay_tz)
            if tz_res:
                relay_ip_str = f" ({target_geo.ip})" if target_geo and getattr(target_geo, "ip", None) else ""
                if tz_res.get("is_discrepancy"):
                    evidence.append(CorrelatedEvidenceItem(
                        source="Forensic/Timezone",
                        finding=(
                            f"Heuristic observation: Email Date header offset ({tz_res['stated_offset']}) "
                            f"diverges by {tz_res['discrepancy_hours']}h from the earliest observable relay timezone "
                            f"({tz_res['relay_timezone']}, {tz_res['relay_offset']}){relay_ip_str} "
                            f"(threshold: {tz_res.get('threshold_hours', 4.0)}h). "
                            "This may indicate upstream mail routing, automated forwarding, or client configuration differences."
                        ),
                        severity="info",
                        details=tz_res,
                        channel="forensic",
                        evidence_class="HEURISTIC",
                    ))
                else:
                    evidence.append(CorrelatedEvidenceItem(
                        source="Forensic/Timezone",
                        finding=(
                            f"Email Date header offset ({tz_res['stated_offset']}) is consistent with the "
                            f"earliest observable relay timezone ({tz_res['relay_timezone']}, {tz_res['relay_offset']}){relay_ip_str}."
                        ),
                        severity="info",
                        details=tz_res,
                        channel="forensic",
                        evidence_class="HEURISTIC",
                    ))

    # ── 4d. Client & Environment Fingerprint ──────────────────────
    if header_intel and getattr(header_intel, "client_fingerprint", None):
        fp = header_intel.client_fingerprint
        if fp.mailer_category in ("Programmatic / Automated Sender", "Automated Script / Bot"):
            evidence.append(CorrelatedEvidenceItem(
                source="Forensic/Fingerprint",
                finding=(
                    f"Sending environment fingerprinted as programmatic / automated sender tool: "
                    f"'{fp.mailer}' (MIME boundary style: {fp.mime_boundary_style})."
                ),
                severity="info",
                details=fp.to_dict(),
                channel="forensic",
                evidence_class="HEURISTIC",
            ))
        elif fp.mailer_category == "Desktop Client":
            evidence.append(CorrelatedEvidenceItem(
                source="Forensic/Fingerprint",
                finding=f"Sending environment fingerprinted as standard desktop MUA: '{fp.mailer}'.",
                severity="info",
                details=fp.to_dict(),
                channel="forensic",
                evidence_class="HEURISTIC",
            ))

        regional_charsets = {"windows-1251", "koi8-r", "iso-8859-5", "gb2312", "euc-kr"}
        found_regional = regional_charsets.intersection(set(fp.charsets_detected))
        if found_regional:
            evidence.append(CorrelatedEvidenceItem(
                source="Forensic/Fingerprint",
                finding=f"Regional character set encoding observed in email headers: {', '.join(found_regional)} (forensic locale clue).",
                severity="info",
                details={
                    "regional_charsets": list(found_regional),
                    "all_charsets": fp.charsets_detected,
                    "disclaimer": getattr(fp, "charset_disclaimer", ""),
                },
                channel="forensic",
                evidence_class="HEURISTIC",
            ))

    # ── 4e. Relay Hop Timeline Analysis ───────────────────────────
    if header_intel and getattr(header_intel, "timeline_analysis", None):
        tl = header_intel.timeline_analysis
        if tl.get("status") == "skew_observed":
            for anomaly in tl.get("anomalies", []):
                evidence.append(CorrelatedEvidenceItem(
                    source="Forensic/Timeline",
                    finding=f"Envelope timeline observation: {anomaly.get('description')}",
                    severity="info",
                    details=anomaly,
                    channel="forensic",
                    evidence_class="DERIVED",
                ))

    # ── 5. Domain Intelligence Signal ─────────────────────────────
    if domain_intel.is_typosquat:
        evidence.append(CorrelatedEvidenceItem(
            source="Domain",
            finding=f"Sender domain '{domain_intel.domain}' exhibits typosquatting characteristics targeting '{domain_intel.typosquat_target}'.",
            severity="high",
            details={"domain": domain_intel.domain, "target_brand": domain_intel.typosquat_target},
        ))
    if domain_intel.age_days is not None and domain_intel.age_days <= 30:
        evidence.append(CorrelatedEvidenceItem(
            source="Domain",
            finding=f"Domain was registered within the last 30 days ({domain_intel.age_days} days ago).",
            severity="medium",
            details={"age_days": domain_intel.age_days},
        ))

    # ── 6. Attachment Signal (Static & Deep Content) ──────────────
    if att_analysis.suspicious_count > 0:
        evidence.append(CorrelatedEvidenceItem(
            source="Attachment",
            finding=f"Email contains {att_analysis.suspicious_count} dangerous or macro-enabled attachment(s).",
            severity="high",
            details={"suspicious_count": att_analysis.suspicious_count},
        ))

    if att_content_analysis:
        for cf in getattr(att_content_analysis, "findings", []):
            if cf.encrypted:
                evidence.append(CorrelatedEvidenceItem(
                    source="Attachment/Content",
                    finding=(
                        f"Attachment '{cf.filename}' is password protected / encrypted. "
                        "Content inspection is limited (password was not bypassed). "
                        "Encrypted files cannot be verified as safe and may conceal malicious payloads."
                    ),
                    severity="medium",
                    details={"filename": cf.filename, "status": "LIMITED", "reason": cf.reason},
                    channel="forensic",
                    evidence_class="OBSERVED",
                ))
            elif cf.content_analysis_status == "ANALYZED":
                if cf.javascript_detected:
                    evidence.append(CorrelatedEvidenceItem(
                        source="Attachment/Content",
                        finding=(
                            f"Attachment '{cf.filename}' contains embedded JavaScript "
                            f"({', '.join(cf.javascript_details[:2]) or 'active script object'}), "
                            "indicating potential client exploit delivery."
                        ),
                        severity="high",
                        details={"filename": cf.filename, "details": cf.javascript_details},
                    ))
                if "/Launch" in cf.actions_detected:
                    evidence.append(CorrelatedEvidenceItem(
                        source="Attachment/Content",
                        finding=(
                            f"Attachment '{cf.filename}' contains a /Launch action designed to execute external applications."
                        ),
                        severity="high",
                        details={"filename": cf.filename, "actions": cf.actions_detected},
                    ))
                elif "/OpenAction" in cf.actions_detected:
                    evidence.append(CorrelatedEvidenceItem(
                        source="Attachment/Content",
                        finding=(
                            f"Attachment '{cf.filename}' contains an automated /OpenAction trigger executing behavior immediately upon opening."
                        ),
                        severity="medium",
                        details={"filename": cf.filename, "actions": cf.actions_detected},
                    ))
                if cf.embedded_files:
                    evidence.append(CorrelatedEvidenceItem(
                        source="Attachment/Content",
                        finding=(
                            f"Attachment '{cf.filename}' contains {len(cf.embedded_files)} embedded file payload(s) ({', '.join(cf.embedded_files[:3])})."
                        ),
                        severity="high",
                        details={"filename": cf.filename, "embedded_files": cf.embedded_files},
                    ))
                if cf.urls:
                    evidence.append(CorrelatedEvidenceItem(
                        source="Attachment/Content",
                        finding=(
                            f"Attachment '{cf.filename}' contains {len(cf.urls)} embedded hyperlink(s) pointing to external domains: {', '.join(cf.domains[:3])}."
                        ),
                        severity="high" if cf.content_risk_score >= 60 else "medium",
                        details={"filename": cf.filename, "urls_count": len(cf.urls), "domains": cf.domains[:5]},
                    ))

    # ── 7. OSINT Intelligence Signal ──────────────────────────────
    has_osint_detection = False
    if osint_result:
        # Check domain OSINT
        for d in osint_result.domains:
            if d.security_observations:
                has_osint_detection = True
                evidence.append(CorrelatedEvidenceItem(
                    source="OSINT",
                    finding=f"Domain '{d.indicator}' has {len(d.security_observations)} public security observation(s) reported by {d.data_source}.",
                    severity="high",
                    details={"indicator": d.indicator, "observations": len(d.security_observations)},
                ))
            for ev in d.evidence:
                evidence.append(CorrelatedEvidenceItem(
                    source="OSINT/Domain",
                    finding=ev.get("finding", "Domain OSINT observation"),
                    severity=ev.get("severity", "medium"),
                ))

        # Check IP OSINT
        for ip in osint_result.ips:
            if ip.security_observations:
                has_osint_detection = True
                evidence.append(CorrelatedEvidenceItem(
                    source="OSINT",
                    finding=f"Observable infrastructure IP '{ip.indicator}' has recorded security observations.",
                    severity="medium",
                    details={"indicator": ip.indicator, "observations": len(ip.security_observations)},
                ))
            for ev in ip.evidence:
                evidence.append(CorrelatedEvidenceItem(
                    source="OSINT/IP",
                    finding=ev.get("finding", "IP OSINT observation"),
                    severity=ev.get("severity", "medium"),
                ))

        # Check URL OSINT
        for u in osint_result.urls:
            if u.security_observations:
                has_osint_detection = True
                evidence.append(CorrelatedEvidenceItem(
                    source="OSINT",
                    finding=f"URL '{u.indicator}' previously reported in threat intelligence repositories.",
                    severity="high",
                    details={"indicator": u.indicator},
                ))
            for ev in u.evidence:
                evidence.append(CorrelatedEvidenceItem(
                    source="OSINT/URL",
                    finding=ev.get("finding", "URL OSINT observation"),
                    severity=ev.get("severity", "high"),
                ))

    # ── 8. Historical Domain / DNS Intelligence (Forensics) ────────
    if forensic_result:
        for d in forensic_result.domains:
            if len(d.historical_ips) > 1:
                evidence.append(CorrelatedEvidenceItem(
                    source="Domain History",
                    finding=f"Domain '{d.domain}' has historical infrastructure changes ({len(d.historical_ips)} observed IPs over time).",
                    severity="medium",
                    details={"domain": d.domain, "historical_ip_count": len(d.historical_ips)},
                ))

    # ── 9. Cross-Vector Synthesis (The Correlation Layer) ─────────
    # Case A: Authentication Failed + ML Phishing = Coordinated Spoofing Campaign
    if auth_failed and is_ml_phish:
        evidence.append(CorrelatedEvidenceItem(
            source="Cross-Vector",
            finding="CORRELATION DETECTED: Email content matches phishing profile while SPF/DMARC authentication failed, indicating an active impersonation attempt.",
            severity="high",
            details={"vectors": ["ML", "Authentication"]},
        ))

    # Case B: ML Phishing + OSINT Detections = Multi-Source Confirmed Threat
    if is_ml_phish and has_osint_detection:
        evidence.append(CorrelatedEvidenceItem(
            source="Cross-Vector",
            finding="CORRELATION DETECTED: NLP phishing signals corroborate public threat intelligence observations on observed infrastructure.",
            severity="high",
            details={"vectors": ["ML", "OSINT"]},
        ))

    # Case C: Suspicious URL + Bulletproof/Offshore Observed IP
    if has_suspicious_url and has_bad_ip:
        evidence.append(CorrelatedEvidenceItem(
            source="Cross-Vector",
            finding="CORRELATION DETECTED: Suspicious URL routing correlates with observed mail relay on high-risk hosting infrastructure.",
            severity="high",
            details={"vectors": ["URL", "IP"]},
        ))

    # Case D: Encrypted Attachment + ML Phishing Prediction = Obfuscated Delivery Campaign
    has_encrypted_att = any(getattr(cf, "encrypted", False) for cf in (getattr(att_content_analysis, "findings", []) or []))
    if has_encrypted_att and is_ml_phish:
        evidence.append(CorrelatedEvidenceItem(
            source="Cross-Vector",
            finding="CORRELATION DETECTED: Email text matches phishing profile while attachment is password protected / encrypted to evade static scanner inspection.",
            severity="high",
            details={"vectors": ["ML", "Attachment/Content"]},
        ))

    # Case E: Attachment Active Exploit Trigger + Authentication Failure = Targeted Exploit Delivery
    has_exploit_att = any(
        getattr(cf, "javascript_detected", False) or ("/Launch" in getattr(cf, "actions_detected", []))
        for cf in (getattr(att_content_analysis, "findings", []) or [])
    )
    if has_exploit_att and auth_failed:
        evidence.append(CorrelatedEvidenceItem(
            source="Cross-Vector",
            finding="CORRELATION DETECTED: Spoofed or unauthenticated sender delivers document attachment with active script/application execution triggers.",
            severity="critical",
            details={"vectors": ["Authentication", "Attachment/Content"]},
        ))

    # ── 10. PhishTank URL Intelligence ────────────────────────────
    has_phishtank_hit = False
    if phishtank_result:
        for r in phishtank_result.results:
            if r.verified and r.valid:
                has_phishtank_hit = True
                evidence.append(CorrelatedEvidenceItem(
                    source="PhishTank",
                    finding=f"URL '{r.url}' is listed as a verified phishing URL in PhishTank (ID: {r.phish_id}).",
                    severity="high",
                    details={
                        "url": r.url,
                        "phish_id": r.phish_id,
                        "type": "url_intelligence",
                        "title": "Known Phishing URL",
                    },
                ))
            elif r.in_database and not r.verified:
                evidence.append(CorrelatedEvidenceItem(
                    source="PhishTank",
                    finding=f"URL '{r.url}' is reported in PhishTank but not yet verified.",
                    severity="medium",
                    details={"url": r.url, "phish_id": r.phish_id},
                ))

    # Case D: PhishTank verified + ML Phishing = Confirmed known phishing campaign
    if has_phishtank_hit and is_ml_phish:
        evidence.append(CorrelatedEvidenceItem(
            source="Cross-Vector",
            finding="CORRELATION DETECTED: NLP phishing classification confirmed by PhishTank verified phishing URL database.",
            severity="high",
            details={"vectors": ["ML", "PhishTank"]},
        ))

    # ── 11. urlscan.io Dynamic URL Sandbox Intelligence ───────────
    has_sandbox_malicious = False
    has_sandbox_downloads = False
    if url_sandbox:
        findings_list = getattr(url_sandbox, "findings", []) or (url_sandbox.get("findings", []) if isinstance(url_sandbox, dict) else [])
        for f in findings_list:
            # Handle both dataclass and dict forms
            f_verdict = getattr(f, "verdict", None) or (f.get("verdict") if isinstance(f, dict) else "")
            f_is_malicious = getattr(f, "is_malicious", False) or (f.get("is_malicious", False) if isinstance(f, dict) else False)
            f_submitted_url = getattr(f, "submitted_url", "") or (f.get("submitted_url", "") if isinstance(f, dict) else "")
            f_effective_url = getattr(f, "effective_url", "") or (f.get("effective_url", "") if isinstance(f, dict) else "")
            f_score = getattr(f, "malicious_score", 0) or (f.get("malicious_score", 0) if isinstance(f, dict) else 0)
            f_categories = getattr(f, "categories", []) or (f.get("categories", []) if isinstance(f, dict) else [])
            f_result_url = getattr(f, "result_url", "") or (f.get("result_url", "") if isinstance(f, dict) else "")
            f_screenshot = getattr(f, "screenshot_url", "") or (f.get("screenshot_url", "") if isinstance(f, dict) else "")
            f_redirects = getattr(f, "redirects", []) or (f.get("redirects", []) if isinstance(f, dict) else [])
            f_downloads = getattr(f, "downloads", []) or (f.get("downloads", []) if isinstance(f, dict) else [])

            if f_verdict == "MALICIOUS" or f_is_malicious:
                has_sandbox_malicious = True
                evidence.append(CorrelatedEvidenceItem(
                    source="urlscan.io Sandbox",
                    finding=(
                        f"Dynamic execution of '{f_submitted_url}' in remote cloud sandbox "
                        f"confirmed MALICIOUS activity (Score: {f_score}/100, "
                        f"Categories: {f_categories or ['phishing']})."
                    ),
                    severity="critical" if f_score >= 80 else "high",
                    details={
                        "url": f_submitted_url,
                        "effective_url": f_effective_url,
                        "report_url": f_result_url,
                        "screenshot_url": f_screenshot,
                        "type": "dynamic_url_sandbox",
                        "title": "Malicious URL Dynamic Execution",
                    },
                ))
            elif f_verdict == "SUSPICIOUS":
                evidence.append(CorrelatedEvidenceItem(
                    source="urlscan.io Sandbox",
                    finding=(
                        f"Dynamic execution of '{f_submitted_url}' revealed suspicious sandbox behavior "
                        f"(Score: {f_score}/100)."
                    ),
                    severity="medium",
                    details={
                        "url": f_submitted_url,
                        "effective_url": f_effective_url,
                        "report_url": f_result_url,
                        "screenshot_url": f_screenshot,
                        "type": "dynamic_url_sandbox",
                        "title": "Suspicious URL Dynamic Execution",
                    },
                ))

            if getattr(f, "content_category", None) == "ADULT_CONTENT" or "ADULT_CONTENT_DETECTED" in (getattr(f, "behavior_indicators", []) or []):
                evidence.append(CorrelatedEvidenceItem(
                    source="urlscan.io Sandbox",
                    finding=f"Adult content detected on destination URL '{f_submitted_url}' (unwanted/suspicious content; not classified as malware).",
                    severity="medium",
                    details={"url": f_submitted_url, "category": "ADULT_CONTENT"},
                ))

            if getattr(f, "status", "") in ("ERROR", "TIMEOUT"):
                evidence.append(CorrelatedEvidenceItem(
                    source="urlscan.io Sandbox",
                    finding=f"Dynamic URL sandbox for '{f_submitted_url}' encountered limitation: Status {getattr(f, 'status', 'ERROR')} ({getattr(f, 'error', 'analysis incomplete')}).",
                    severity="info",
                    details={"url": f_submitted_url, "status": getattr(f, "status", "ERROR")},
                ))

            # Dynamic redirect unmasking
            if f_redirects or (f_effective_url and f_submitted_url and f_effective_url.rstrip("/").lower() != f_submitted_url.rstrip("/").lower()):
                evidence.append(CorrelatedEvidenceItem(
                    source="urlscan.io Sandbox",
                    finding=f"Dynamic URL sandbox unmasked redirection: '{f_submitted_url}' redirected to '{f_effective_url}'.",
                    severity="medium",
                    details={
                        "submitted_url": f_submitted_url,
                        "effective_url": f_effective_url,
                        "redirect_count": len(f_redirects),
                    },
                ))

            # Download detection
            if f_downloads:
                has_sandbox_downloads = True
                for dl in f_downloads:
                    dl_name = dl.get("filename") if isinstance(dl, dict) else getattr(dl, "filename", "")
                    dl_mime = dl.get("mime_type") if isinstance(dl, dict) else getattr(dl, "mime_type", "")
                    dl_url = dl.get("url") if isinstance(dl, dict) else getattr(dl, "url", "")
                    evidence.append(CorrelatedEvidenceItem(
                        source="urlscan.io Sandbox",
                        finding=f"Dynamic sandbox intercepted payload download: '{dl_name}' ({dl_mime}) from {dl_url}.",
                        severity="high",
                        details={
                            "url": dl_url,
                            "filename": dl_name,
                            "mime_type": dl_mime,
                        },
                    ))

    # Cross-vector correlation: Sandbox malicious + ML Phishing
    if has_sandbox_malicious and is_ml_phish:
        evidence.append(CorrelatedEvidenceItem(
            source="Cross-Vector",
            finding="CORRELATION DETECTED: Remote urlscan.io dynamic execution confirmed malicious URL in email classified as phishing by ML.",
            severity="critical",
            details={"vectors": ["ML", "urlscan.io Sandbox"]},
        ))

    # Cross-vector correlation: Sandbox payload download
    if has_sandbox_downloads:
        evidence.append(CorrelatedEvidenceItem(
            source="Cross-Vector",
            finding="CORRELATION DETECTED: Dynamic URL analysis detected payload download linked to email content.",
            severity="high",
            details={"vectors": ["URL Sandbox", "Download/Payload"]},
        ))

    # Convert to standard dict representations
    return [item.to_dict() for item in evidence]
