"""
GmailGuard — Report Generator

Assembles all analysis results into the final structured JSON report
matching the GmailGuard output schema.
"""

from __future__ import annotations

from typing import Any

from authentication_analyzer import AuthResult
from ip_intelligence import IPIntelligence
from geolocation import GeoRecord
from url_analyzer import URLAnalysis
from attachment_analyzer import AttachmentAnalysis
from ml_classifier import MLResult
from domain_intelligence import DomainIntelligence
from header_analyzer import HeaderIntelligence
from threat_scorer import ThreatScore
from email_parser import ParsedEmail
from forensic_domain_intelligence import ForensicIntelligenceResult, DomainForensicResult
import config
from typing import Optional
try:
    from osint_intelligence import OSINTAnalysisResult
except ImportError:
    OSINTAnalysisResult = Any


def generate_report(
    parsed: ParsedEmail,
    auth: AuthResult,
    header_intel: HeaderIntelligence,
    ip_intel: IPIntelligence,
    geo_records: list[GeoRecord],
    url_analysis: URLAnalysis,
    att_analysis: AttachmentAnalysis,
    ml: MLResult,
    domain_intel: DomainIntelligence,
    threat_score: ThreatScore,
    forensic_result: Optional[ForensicIntelligenceResult] = None,
    osint_result: Optional[OSINTAnalysisResult] = None,
    correlated_evidence: Optional[list[dict[str, Any]]] = None,
    phishtank_result: Optional[Any] = None,
) -> dict[str, Any]:
    """
    Generate the final structured forensic report.

    Returns a JSON-serializable dict matching the GmailGuard output schema.
    """

    # ── Email metadata ───────────────────────────────────────────
    email_meta = {
        "from": parsed.raw_from,
        "sender_email": parsed.sender_email,
        "sender_name": parsed.sender_name,
        "sender_domain": parsed.sender_domain,
        "reply_to": parsed.reply_to,
        "to": parsed.to,
        "subject": parsed.subject,
        "date": parsed.date,
        "message_id": parsed.message_id,
    }

    # ── Authentication ───────────────────────────────────────────
    authentication = {
        "spf":   auth.spf,
        "dkim":  auth.dkim,
        "dmarc": auth.dmarc,
        "spf_detail":   auth.spf_detail,
        "dkim_detail":  auth.dkim_detail,
        "dmarc_detail": auth.dmarc_detail,
        "summary": auth.summary,
    }

    # ── Infrastructure ───────────────────────────────────────────
    geo_list = [
        g.to_dict() if hasattr(g, "to_dict") else {
            "ip":            g.ip,
            "country":       g.country,
            "region":        g.region,
            "city":          g.city,
            "lat":           g.lat,
            "lon":           g.lon,
            "latitude":      getattr(g, "latitude", g.lat),
            "longitude":     getattr(g, "longitude", g.lon),
            "asn":           g.asn,
            "isp":           g.isp,
            "org":           g.org,
            "organization":  getattr(g, "organization", g.org),
            "postal":        getattr(g, "postal", None),
            "timezone":      getattr(g, "timezone", None),
            "hostname":      getattr(g, "hostname", None),
            "network":       getattr(g, "network", None),
            "source":        g.source,
            "status":        getattr(g, "status", "success"),
            "location_type": getattr(g, "location_type", "observable_infrastructure"),
            "location_note": getattr(g, "location_note", g.forensic_note),
            "forensic_note": g.forensic_note,
        }
        for g in geo_records
    ]

    ip_records_list = [
        {
            "ip":               r.ip,
            "reputation":       r.reputation,
            "reputation_score": r.reputation_score,
            "categories":       r.categories,
            "source":           r.source,
            "is_observable_infra": r.is_observable_infra,
        }
        for r in ip_intel.records
    ]

    relay_chain_list = [
        {
            "from_host": h.from_host,
            "by_host":   h.by_host,
            "ip":        h.ip,
            "provider":  h.provider,
        }
        for h in header_intel.relay_chain
    ]

    chronological_hops_list = [
        {
            "hop_number": getattr(h, "hop_number", idx),
            "from_host": h.from_host,
            "by_host": h.by_host,
            "ip": h.ip,
            "provider": h.provider,
            "is_private": getattr(h, "is_private", False),
            "is_upstream_origin": getattr(h, "is_upstream_origin", False),
            "raw": getattr(h, "raw", ""),
            "timestamp_raw": getattr(h, "timestamp_raw", None),
            "timestamp_utc": getattr(h, "timestamp_utc", None),
            "provenance": getattr(h, "provenance", "UNKNOWN"),
            "confidence": getattr(h, "confidence", "medium"),
            "evidence_class": getattr(h, "evidence_class", "DERIVED"),
        }
        for idx, h in enumerate(getattr(header_intel, "chronological_hops", []), start=1)
    ]

    client_fp_dict = None
    if getattr(header_intel, "client_fingerprint", None):
        client_fp_dict = header_intel.client_fingerprint.to_dict()

    timezone_analysis = None
    if parsed and getattr(parsed, "date", None) and geo_records:
        target_geo = next((g for g in geo_records if getattr(g, "timezone", None) and g.timezone != "UNKNOWN"), None)
        if target_geo:
            from evidence_correlator import correlate_timezone
            timezone_analysis = correlate_timezone(parsed.date, target_geo.timezone)

    infrastructure = {
        "forensic_scope":        getattr(config, "FORENSIC_SCOPE_DISCLAIMER", "Physical attribution is outside the scope of email-header analysis and may require additional evidence and lawful investigative processes."),
        "upstream_relay_ip":     getattr(header_intel, "upstream_relay_ip", None),
        "candidate_relays":      getattr(header_intel, "candidate_relays", []),
        "timeline_analysis":     getattr(header_intel, "timeline_analysis", {}),
        "chronological_hops":    chronological_hops_list,
        "client_fingerprint":    client_fp_dict,
        "timezone_correlation":  timezone_analysis,
        "x_originating_ip":      header_intel.x_originating_ip or None,
        "x_mailer":              header_intel.x_mailer or None,
        "relay_chain":           relay_chain_list,
        "identified_providers":  header_intel.identified_providers,
        "infrastructure_note":   header_intel.infrastructure_note,
        "public_ips":            ip_intel.public_ips,
        "ip_records":            ip_records_list,
        "geolocation":           geo_list,
        "reply_to_differs":      header_intel.reply_to_differs,
    }

    # ── URLs ─────────────────────────────────────────────────────
    url_findings_list = [
        {
            "url":                    f.url,
            "domain":                 f.domain,
            "tld":                    f.tld,
            "risk_score":             f.risk_score,
            "is_ip_url":              f.is_ip_url,
            "is_url_shortener":       f.is_url_shortener,
            "has_suspicious_tld":     f.has_suspicious_tld,
            "excessive_subdomains":   f.excessive_subdomains,
            "has_suspicious_chars":   f.has_suspicious_chars,
            "uses_https":             f.uses_https,
            "display_href_mismatch":  f.display_href_mismatch,
            "domain_reputation":      f.domain_reputation,
            "domain_rep_score":       f.domain_rep_score,
            "reasons":                f.reasons,
        }
        for f in url_analysis.findings
    ]

    urls_section = {
        "count":      url_analysis.total_count,
        "suspicious": url_analysis.suspicious_count,
        "all_urls":   url_analysis.all_urls,
        "findings":   url_findings_list,
        "limitations": url_analysis.limitations,
    }

    # ── Attachments ──────────────────────────────────────────────
    att_findings_list = [
        {
            "filename":                    f.filename,
            "extension":                   f.extension,
            "content_type":                f.content_type,
            "size_bytes":                  f.size_bytes,
            "size_mb":                     f.size_mb,
            "risk_score":                  f.risk_score,
            "is_dangerous_extension":      f.is_dangerous_extension,
            "is_archive":                  f.is_archive,
            "is_macro_enabled":            f.is_macro_enabled,
            "has_double_extension":        f.has_double_extension,
            "suspicious_filename_keywords": f.suspicious_filename_keywords,
            "magic_byte_matches":          f.magic_byte_matches,
            "size_exceeds_limit":          f.size_exceeds_limit,
            "mime_extension_mismatch":     f.mime_extension_mismatch,
            "reasons":                     f.reasons,
        }
        for f in att_analysis.findings
    ]

    attachments_section = {
        "count":      att_analysis.total_count,
        "suspicious": att_analysis.suspicious_count,
        "findings":   att_findings_list,
    }

    # ── ML ───────────────────────────────────────────────────────
    ml_section = {
        "prediction":      ml.prediction,
        "decision_score":  ml.decision_score,
        "model_available": ml.model_available,
        "note":            ml.note,
    }

    # ── Domain Intelligence ──────────────────────────────────────
    domain_section = {
        "domain":            domain_intel.domain,
        "reputation":        domain_intel.reputation,
        "reputation_score":  domain_intel.reputation_score,
        "categories":        domain_intel.categories,
        "age_days":          domain_intel.age_days,
        "registrar":         domain_intel.registrar,
        "virustotal_flags":  domain_intel.virustotal_flags,
        "is_suspicious_tld": domain_intel.is_suspicious_tld,
        "is_typosquat":      domain_intel.is_typosquat,
        "typosquat_target":  domain_intel.typosquat_target,
        "risk_score":        domain_intel.risk_score,
        "reasons":           domain_intel.reasons,
    }

    # ── Evidence ─────────────────────────────────────────────────
    def ev_to_dict(e) -> dict:
        return {
            "signal":      e.signal,
            "status":      e.status,
            "impact":      e.impact,
            "explanation": e.explanation,
        }

    evidence_list        = [ev_to_dict(e) for e in threat_score.evidence]
    positive_evidence_list = [ev_to_dict(e) for e in threat_score.positive_evidence]

    # ── Parse errors ─────────────────────────────────────────────
    all_limitations = list(threat_score.limitations)
    if parsed.parse_errors:
        all_limitations.extend([f"Parse warning: {e}" for e in parsed.parse_errors])

    # ── Forensics ────────────────────────────────────────────
    def _serialize_domain_forensic(d: DomainForensicResult) -> dict:
        return {
            "domain":      d.domain,
            "data_source": d.data_source,
            "current_dns": {
                "A":     d.current_dns.A,
                "AAAA":  d.current_dns.AAAA,
                "MX":    d.current_dns.MX,
                "NS":    d.current_dns.NS,
                "CNAME": d.current_dns.CNAME,
                "TXT":   d.current_dns.TXT,
            },
            "historical_dns": {
                rtype: [
                    {
                        "value":      r.value,
                        "first_seen": r.first_seen,
                        "last_seen":  r.last_seen,
                    }
                    for r in records
                ]
                for rtype, records in d.historical_dns.items()
            },
            "historical_ips": [
                {"ip": h.ip, "first_seen": h.first_seen, "last_seen": h.last_seen}
                for h in d.historical_ips
            ],
            "whois_history": [
                {
                    "registrar":   w.registrar,
                    "registered":  w.registered,
                    "updated":     w.updated,
                    "expires":     w.expires,
                    "nameservers": w.nameservers,
                }
                for w in d.whois_history
            ],
            "security_history": {
                "previously_detected": d.security_history.previously_detected,
                "currently_detected":  d.security_history.currently_detected,
                "detections": [
                    {
                        "date":     det.date,
                        "category": det.category,
                        "provider": det.provider,
                    }
                    for det in d.security_history.detections
                ],
            },
            "timeline": [
                {
                    "date":   e.date,
                    "event":  e.event,
                    "value":  e.value,
                    "source": e.source,
                }
                for e in d.timeline
            ],
            "evidence": [
                {
                    "type":        ev.type,
                    "severity":    ev.severity,
                    "description": ev.description,
                    "evidence":    ev.evidence,
                    "source":      ev.source,
                }
                for ev in d.evidence
            ],
            "limitations": d.limitations,
        }

    forensics_section: dict[str, Any] = {
        "domains":     [_serialize_domain_forensic(d) for d in forensic_result.domains] if forensic_result else [],
        "limitations": list(forensic_result.limitations) if forensic_result else [],
    }

    if osint_result:
        forensics_section["osint"] = {
            "domains": [d.to_dict() for d in osint_result.domains],
            "ips": [ip.to_dict() for ip in osint_result.ips],
            "urls": [u.to_dict() for u in osint_result.urls],
            "data_source": osint_result.data_source,
            "limitations": osint_result.limitations,
        }
        if osint_result.limitations:
            forensics_section["limitations"].extend(osint_result.limitations)

    if correlated_evidence:
        forensics_section["correlated_evidence"] = correlated_evidence

    if phishtank_result:
        forensics_section["phishtank"] = phishtank_result.to_dict()

    forensic_anomalies = [
        item for item in (correlated_evidence or [])
        if item.get("channel") == "forensic" or str(item.get("source", "")).startswith("Forensic/")
    ]

    # ── Final report ─────────────────────────────────────────────
    report: dict[str, Any] = {
        "threat_score": threat_score.threat_score,
        "verdict":      threat_score.verdict,

        "email":            email_meta,
        "authentication":   authentication,
        "infrastructure":   infrastructure,
        "domain":           domain_section,
        "urls":             urls_section,
        "attachments":      attachments_section,
        "ml":               ml_section,

        "evidence":          evidence_list,
        "positive_evidence": positive_evidence_list,

        "sub_scores":    threat_score.sub_scores,
        "weights_used":  threat_score.weights_used,
        "limitations":   all_limitations,
        
        "forensics":           forensics_section,
        "forensic_anomalies":  forensic_anomalies,
        "correlated_evidence": correlated_evidence or [],
    }

    return report
