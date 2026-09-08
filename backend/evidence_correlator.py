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

from dataclasses import dataclass, field
from typing import Any, Optional

from ml_classifier import MLResult
from authentication_analyzer import AuthResult
from ip_intelligence import IPIntelligence
from domain_intelligence import DomainIntelligence
from url_analyzer import URLAnalysis
from attachment_analyzer import AttachmentAnalysis
from osint_intelligence import OSINTAnalysisResult
from forensic_domain_intelligence import ForensicIntelligenceResult


@dataclass
class CorrelatedEvidenceItem:
    """A single piece of correlated evidence with source attribution."""
    source: str           # "ML", "Authentication", "URL", "IP", "Domain", "OSINT", "Cross-Vector"
    finding: str          # Clear factual explanation
    severity: str         # "info", "low", "medium", "high", "critical"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "finding": self.finding,
            "severity": self.severity,
            "details": self.details,
        }


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
) -> list[dict[str, Any]]:
    """
    Correlate findings across ML, Authentication, URLs, Infrastructure, OSINT, and PhishTank.
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

    # ── 6. Attachment Signal ──────────────────────────────────────
    if att_analysis.suspicious_count > 0:
        evidence.append(CorrelatedEvidenceItem(
            source="Attachment",
            finding=f"Email contains {att_analysis.suspicious_count} dangerous or macro-enabled attachment(s).",
            severity="high",
            details={"suspicious_count": att_analysis.suspicious_count},
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

    # Convert to standard dict representations
    return [item.to_dict() for item in evidence]
