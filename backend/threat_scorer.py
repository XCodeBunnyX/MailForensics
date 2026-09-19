"""
GmailGuard — Threat Scorer

Combines signals from all analysis modules into a single normalized
threat score (0-100) using configurable weights from config.py.

Design principles:
  - Each signal produces a sub-score in range [0, 100].
  - UNKNOWN / NONE → neutral sub-score (50), never malicious.
  - Weighted sum → final score.
  - Evidence items explain WHY the score was generated.
  - Positive evidence (things that reduce risk) is also surfaced.
  - Geolocation contributes forensic context only (no direct score delta).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

from . import config
from .authentication_analyzer import AuthResult
from .ip_intelligence import IPIntelligence
from .url_analyzer import URLAnalysis
from .attachment_analyzer import AttachmentAnalysis
from .ml_classifier import MLResult
from .domain_intelligence import DomainIntelligence
from .header_analyzer import HeaderIntelligence


@dataclass
class EvidenceItem:
    """A single piece of forensic evidence contributing to the score."""
    signal: str          # which signal produced this
    status: str          # e.g. FAIL, PASS, PHISHING, SUSPICIOUS
    impact: str          # HIGH | MEDIUM | LOW | POSITIVE
    explanation: str     # human-readable explanation
    is_positive: bool = False  # True → evidence REDUCES risk


@dataclass
class ThreatScore:
    """Final combined threat scoring result."""
    threat_score: int                    # 0-100
    verdict: str                         # CLEAN | LOW_RISK | MEDIUM_RISK | HIGH_RISK | CRITICAL

    # Per-signal sub-scores (0-100 each)
    sub_scores: dict[str, int]

    # Evidence
    evidence: list[EvidenceItem]         # negative evidence (risk factors)
    positive_evidence: list[EvidenceItem]  # positive evidence (good signals)

    # Limitations & caveats
    limitations: list[str]

    # Signal weights used (snapshot from config at time of scoring)
    weights_used: dict[str, float]


# ── Helpers ──────────────────────────────────────────────────────

def _impact_label(sub_score: int) -> str:
    """Convert a sub-score to an impact label."""
    if sub_score >= config.EVIDENCE_IMPACT_HIGH:
        return "HIGH"
    elif sub_score >= config.EVIDENCE_IMPACT_MEDIUM:
        return "MEDIUM"
    else:
        return "LOW"


def _get_verdict(score: int) -> str:
    for threshold, label in config.VERDICT_THRESHOLDS:
        if score >= threshold:
            return label
    return "CLEAN"


# ── Signal sub-score calculators ─────────────────────────────────

def _score_ml(ml: MLResult) -> tuple[int, list[EvidenceItem]]:
    """
    Compute sub-score from ML prediction.
    Phishing → high score  |  Legitimate → low score  |  UNKNOWN → neutral 50
    """
    evidence: list[EvidenceItem] = []

    if not ml.model_available or ml.prediction == "UNKNOWN":
        return 50, []   # neutral

    if ml.prediction == "Phishing":
        # Scale using decision score: large positive → more confident phishing
        base = 75
        if ml.decision_score is not None:
            # Clip to [-CLIP, CLIP], rescale to add up to 25 extra points
            clipped = max(-config.ML_DECISION_SCORE_CLIP,
                          min(config.ML_DECISION_SCORE_CLIP, ml.decision_score))
            extra = int((clipped / config.ML_DECISION_SCORE_CLIP) * 25)
            sub_score = min(base + extra, 100)
        else:
            sub_score = base

        evidence.append(EvidenceItem(
            signal="ML/NLP",
            status="PHISHING",
            impact=_impact_label(sub_score),
            explanation=(
                f"NLP classifier predicted 'Phishing' "
                f"(decision score: {ml.decision_score:.3f} — raw discriminant, not a probability). "
                "Email content matches phishing linguistic patterns."
            ),
        ))
        return sub_score, evidence

    else:  # Legitimate
        base = 20
        if ml.decision_score is not None:
            clipped = max(-config.ML_DECISION_SCORE_CLIP,
                          min(config.ML_DECISION_SCORE_CLIP, ml.decision_score))
            # Negative score → more confidently legitimate → lower sub-score
            extra = int((-clipped / config.ML_DECISION_SCORE_CLIP) * 15)
            sub_score = max(base - extra, 5)
        else:
            sub_score = base

        evidence.append(EvidenceItem(
            signal="ML/NLP",
            status="LEGITIMATE",
            impact="POSITIVE",
            explanation="NLP classifier predicted 'Legitimate' email content.",
            is_positive=True,
        ))
        return sub_score, evidence


def _score_authentication(auth: AuthResult) -> tuple[int, list[EvidenceItem]]:
    """Compute sub-score from SPF / DKIM / DMARC results."""
    evidence: list[EvidenceItem] = []
    total = 0.0

    for proto, result in [("SPF", auth.spf), ("DKIM", auth.dkim), ("DMARC", auth.dmarc)]:
        sub = config.AUTH_SCORE_MAP.get(result, 50)
        weight = config.AUTH_SUB_WEIGHTS.get(proto.lower(), 1/3)
        total += sub * weight

        if result == "PASS":
            evidence.append(EvidenceItem(
                signal=proto,
                status="PASS",
                impact="POSITIVE",
                explanation=(
                    f"{proto} passed. Note: a {proto} pass does NOT guarantee "
                    "the email is safe — it only proves the sending server is "
                    "authorized for that domain."
                ),
                is_positive=True,
            ))
        elif result in ("FAIL", "SOFTFAIL", "PERMERROR"):
            evidence.append(EvidenceItem(
                signal=proto,
                status=result,
                impact=_impact_label(sub),
                explanation=f"{proto} {result}: email authentication alignment failed.",
            ))
        else:
            # NONE / UNKNOWN / NEUTRAL — no evidence item, neutral contribution
            pass

    return int(round(total)), evidence


def _score_ip(ip_intel: IPIntelligence) -> tuple[int, list[EvidenceItem]]:
    """Compute sub-score from IP reputation."""
    evidence: list[EvidenceItem] = []

    if not ip_intel.records:
        return 50, []   # no IPs observed → neutral

    # Use the worst-case IP reputation score
    sub_score = ip_intel.max_reputation_score

    for record in ip_intel.records:
        if record.reputation == "malicious":
            evidence.append(EvidenceItem(
                signal="IP Reputation",
                status="MALICIOUS",
                impact=_impact_label(record.reputation_score),
                explanation=(
                    f"Observable relay IP {record.ip} has malicious reputation "
                    f"(categories: {record.categories}, source: {record.source}). "
                    "This is relay infrastructure, not necessarily the sender's device."
                ),
            ))
        elif record.reputation == "suspicious":
            evidence.append(EvidenceItem(
                signal="IP Reputation",
                status="SUSPICIOUS",
                impact=_impact_label(record.reputation_score),
                explanation=(
                    f"Observable relay IP {record.ip} has suspicious reputation "
                    f"(categories: {record.categories})."
                ),
            ))
        elif record.reputation == "clean":
            evidence.append(EvidenceItem(
                signal="IP Reputation",
                status="CLEAN",
                impact="POSITIVE",
                explanation=f"Observable relay IP {record.ip} has clean reputation.",
                is_positive=True,
            ))

    return sub_score, evidence


def _score_domain(domain_intel: DomainIntelligence) -> tuple[int, list[EvidenceItem]]:
    """Compute sub-score from domain intelligence."""
    evidence: list[EvidenceItem] = []
    sub_score = domain_intel.risk_score

    for reason in domain_intel.reasons:
        evidence.append(EvidenceItem(
            signal="Domain Intelligence",
            status=domain_intel.reputation.upper(),
            impact=_impact_label(sub_score),
            explanation=reason,
        ))

    if not domain_intel.reasons and domain_intel.reputation == "clean":
        evidence.append(EvidenceItem(
            signal="Domain Intelligence",
            status="CLEAN",
            impact="POSITIVE",
            explanation=f"Sender domain '{domain_intel.domain}' has clean reputation.",
            is_positive=True,
        ))

    return sub_score, evidence


def _score_urls(
    url_analysis: URLAnalysis,
    url_sandbox: Optional[Any] = None,
) -> tuple[int, list[EvidenceItem]]:
    """Compute sub-score from static URL analysis and dynamic sandbox analysis."""
    evidence: list[EvidenceItem] = []

    has_urls = url_analysis.total_count > 0 or (url_sandbox and getattr(url_sandbox, "total_scanned", 0) > 0)
    if not has_urls:
        return 10, []   # no URLs → low risk contribution

    max_url_score = max((f.risk_score for f in url_analysis.findings), default=0)

    # Static URL evidence
    for finding in url_analysis.findings:
        if finding.risk_score >= 30:
            evidence.append(EvidenceItem(
                signal="URL Analysis",
                status="SUSPICIOUS" if finding.risk_score < 60 else "MALICIOUS",
                impact=_impact_label(finding.risk_score),
                explanation=(
                    f"URL '{finding.url[:80]}' — "
                    + "; ".join(finding.reasons[:3])
                ),
            ))

    # Dynamic sandbox findings (urlscan.io)
    if url_sandbox:
        for sf in getattr(url_sandbox, "findings", []):
            if sf.verdict == "MALICIOUS" or sf.is_malicious:
                max_url_score = max(max_url_score, max(sf.malicious_score, 80))
                evidence.append(EvidenceItem(
                    signal="URL Dynamic Sandbox",
                    status="MALICIOUS",
                    impact="HIGH",
                    explanation=(
                        f"urlscan.io dynamic execution flagged URL '{sf.submitted_url[:70]}' as MALICIOUS "
                        f"(score: {sf.malicious_score}/100) — " + "; ".join(sf.reasons[:2])
                    ),
                ))
            elif getattr(sf, "content_category", None) == "ADULT_CONTENT" or "ADULT_CONTENT_DETECTED" in getattr(sf, "behavior_indicators", []):
                # Adult content contributes to suspicious/unwanted-content assessment, NOT malware
                max_url_score = max(max_url_score, 40)
                evidence.append(EvidenceItem(
                    signal="URL Dynamic Sandbox",
                    status="SUSPICIOUS",
                    impact="MEDIUM",
                    explanation=(
                        f"Adult content detected on destination URL '{sf.submitted_url[:70]}' "
                        "(unwanted/suspicious content; not classified as malware)."
                    ),
                ))
            elif sf.verdict == "SUSPICIOUS" or (sf.downloads and len(sf.downloads) > 0):
                max_url_score = max(max_url_score, max(sf.malicious_score, 45))
                dl_note = f" Triggered download of {len(sf.downloads)} payload(s)." if sf.downloads else ""
                evidence.append(EvidenceItem(
                    signal="URL Dynamic Sandbox",
                    status="SUSPICIOUS",
                    impact="MEDIUM",
                    explanation=(
                        f"urlscan.io dynamic execution detected suspicious behavior on '{sf.submitted_url[:70]}'.{dl_note} "
                        + "; ".join(sf.reasons[:2])
                    ),
                ))
            elif sf.verdict == "CLEAN" and not any(e.status in ("SUSPICIOUS", "MALICIOUS") for e in evidence):
                evidence.append(EvidenceItem(
                    signal="URL Dynamic Sandbox",
                    status="CLEAN",
                    impact="POSITIVE",
                    explanation=f"urlscan.io dynamic execution completed with no threats detected for '{sf.submitted_url[:70]}'.",
                    is_positive=True,
                ))

    if not evidence and url_analysis.suspicious_count == 0:
        evidence.append(EvidenceItem(
            signal="URL Analysis",
            status="CLEAN",
            impact="POSITIVE",
            explanation=f"All {url_analysis.total_count} URL(s) passed static analysis.",
            is_positive=True,
        ))
        return 10, evidence

    # Calculate sub-score proportionally
    prop = (url_analysis.suspicious_count / url_analysis.total_count) if url_analysis.total_count else 0.5
    sub_score = int(max_url_score * 0.7 + prop * 30) if url_analysis.total_count else max_url_score
    if any(e.status in ("MALICIOUS", "SUSPICIOUS") for e in evidence):
        sub_score = max(sub_score, max_url_score)

    return min(max(sub_score, 10), 100), evidence


def _score_attachments(
    att_analysis: AttachmentAnalysis,
    att_content_analysis: Optional[Any] = None,
) -> tuple[int, list[EvidenceItem]]:
    """Compute sub-score from attachment analysis (static + deep content)."""
    evidence: list[EvidenceItem] = []

    if att_analysis.total_count == 0:
        return 0, []   # no attachments → zero contribution

    max_score = max((f.risk_score for f in att_analysis.findings), default=0)

    for finding in att_analysis.findings:
        if finding.risk_score >= 30:
            evidence.append(EvidenceItem(
                signal="Attachment Analysis",
                status="SUSPICIOUS",
                impact=_impact_label(finding.risk_score),
                explanation=(
                    f"Attachment '{finding.filename}' — "
                    + "; ".join(finding.reasons[:3])
                ),
            ))

    # Deep content findings integration
    if att_content_analysis:
        for cf in getattr(att_content_analysis, "findings", []):
            if cf.encrypted:
                # Cautious impact: encryption obscures inspection
                evidence.append(EvidenceItem(
                    signal="Attachment Content",
                    status="LIMITED",
                    impact="MEDIUM",
                    explanation=(
                        f"Attachment '{cf.filename}' is password protected / encrypted. "
                        "Content cannot be verified safe and is marked UNKNOWN / NOT ANALYZABLE."
                    ),
                ))
            elif cf.content_analysis_status == "ANALYZED":
                if cf.javascript_detected:
                    max_score = max(max_score, 80)
                    evidence.append(EvidenceItem(
                        signal="Attachment Content",
                        status="DANGEROUS",
                        impact="HIGH",
                        explanation=(
                            f"Attachment '{cf.filename}' contains embedded JavaScript code or script tokens."
                        ),
                    ))
                if "/Launch" in cf.actions_detected:
                    max_score = max(max_score, 85)
                    evidence.append(EvidenceItem(
                        signal="Attachment Content",
                        status="DANGEROUS",
                        impact="HIGH",
                        explanation=(
                            f"Attachment '{cf.filename}' contains a /Launch action executing external commands."
                        ),
                    ))
                elif "/OpenAction" in cf.actions_detected:
                    max_score = max(max_score, 60)
                    evidence.append(EvidenceItem(
                        signal="Attachment Content",
                        status="SUSPICIOUS",
                        impact="MEDIUM",
                        explanation=(
                            f"Attachment '{cf.filename}' contains an automated /OpenAction execution trigger."
                        ),
                    ))
                if cf.embedded_files:
                    max_score = max(max_score, 75)
                    evidence.append(EvidenceItem(
                        signal="Attachment Content",
                        status="SUSPICIOUS",
                        impact="HIGH",
                        explanation=(
                            f"Attachment '{cf.filename}' encapsulates embedded internal file payloads."
                        ),
                    ))

            if cf.content_risk_score >= 30 and not any(e.signal == "Attachment Content" and cf.filename in e.explanation for e in evidence):
                evidence.append(EvidenceItem(
                    signal="Attachment Content",
                    status="DANGEROUS" if cf.content_risk_score >= 60 else "SUSPICIOUS",
                    impact="HIGH" if cf.content_risk_score >= 60 else "MEDIUM",
                    explanation=(
                        f"Attachment '{cf.filename}' contains suspicious/high-risk content or embedded URLs "
                        f"(Verdict: {cf.content_verdict}, Risk Score: {cf.content_risk_score}/100) — "
                        + "; ".join(cf.reasons[:2])
                    ),
                ))

            if cf.content_risk_score > max_score:
                max_score = cf.content_risk_score

    # Check if any attachment is encrypted, limited, or unanalyzable
    has_unverified = False
    if att_content_analysis:
        for cf in getattr(att_content_analysis, "findings", []):
            if cf.encrypted or cf.content_analysis_status in ("LIMITED", "FAILED", "UNSUPPORTED") or cf.content_verdict in ("NOT_ANALYZABLE", "UNKNOWN"):
                has_unverified = True
                break

    if not evidence and att_analysis.suspicious_count == 0:
        if has_unverified:
            evidence.append(EvidenceItem(
                signal="Attachment Analysis",
                status="NOT_ANALYZABLE",
                impact="MEDIUM",
                explanation="Attachment contains encrypted, limited, or unanalyzable files; contents could not be verified safe.",
                is_positive=False,
            ))
            return max(35, max_score), evidence
        else:
            evidence.append(EvidenceItem(
                signal="Attachment Analysis",
                status="NO_THREATS_DETECTED",
                impact="POSITIVE",
                explanation="No suspicious attachment characteristics or dangerous content detected by analyzers.",
                is_positive=True,
            ))
            return 10, evidence

    return min(max_score, 100), evidence


def _collect_limitations(
    ip_intel: IPIntelligence,
    url_analysis: URLAnalysis,
    ml: MLResult,
    header_intel: HeaderIntelligence,
    att_content_analysis: Optional[Any] = None,
    url_sandbox: Optional[Any] = None,
    geo_records: Optional[Any] = None,
) -> list[str]:
    limitations: list[str] = []
    limitations.extend(ip_intel.limitations)
    limitations.extend(url_analysis.limitations)
    if not ml.model_available:
        limitations.append(ml.note)
    for warn in header_intel.warnings:
        limitations.append(warn)

    if att_content_analysis:
        for cf in getattr(att_content_analysis, "findings", []):
            if cf.encrypted:
                limitations.append(
                    f"Attachment '{cf.filename}' is password protected; content analysis was limited."
                )
            elif cf.content_analysis_status == "FAILED":
                limitations.append(
                    f"Attachment '{cf.filename}' content parsing encountered an error: {cf.reason or 'malformed'}"
                )

    if url_sandbox:
        limitations.extend(getattr(url_sandbox, "limitations", []))
        for sf in getattr(url_sandbox, "findings", []):
            if sf.status in ("ERROR", "TIMEOUT", "FAILED"):
                limitations.append(
                    f"urlscan.io sandbox for '{sf.submitted_url[:50]}': Status {sf.status} (Reason: {sf.error or 'analysis incomplete'})"
                )
            elif sf.verdict == "UNKNOWN" and getattr(sf, "mode", "") == "MOCK":
                limitations.append(
                    f"urlscan.io sandbox for '{sf.submitted_url[:50]}': Mock mode (inconclusive / UNKNOWN; live analysis not executed)"
                )

    if geo_records:
        for g in geo_records:
            status = getattr(g, "status", "success")
            if status in ("error", "unavailable", "not_found"):
                reason = getattr(g, "reason", "no intelligence returned")
                limitations.append(
                    f"IPinfo observable infrastructure for {g.ip}: Status {status.upper()} (Reason: {reason})"
                )

    return limitations


# ── Main scoring function ─────────────────────────────────────────

def compute_threat_score(
    ml: MLResult,
    auth: AuthResult,
    ip_intel: IPIntelligence,
    domain_intel: DomainIntelligence,
    url_analysis: URLAnalysis,
    att_analysis: AttachmentAnalysis,
    header_intel: HeaderIntelligence,
    att_content_analysis: Optional[Any] = None,
    url_sandbox: Optional[Any] = None,
    geo_records: Optional[Any] = None,
) -> ThreatScore:
    """
    Compute a normalized, explainable threat score from all signals.

    Args:
        ml:           ML classifier result
        auth:         Authentication (SPF/DKIM/DMARC) result
        ip_intel:     IP intelligence result
        domain_intel: Domain intelligence result
        url_analysis: URL analysis result
        att_analysis: Attachment analysis result
        header_intel: Header analysis result
        att_content_analysis: Optional deep attachment content analysis
        url_sandbox:  Optional dynamic urlscan.io sandbox analysis
        geo_records:  Optional observable infrastructure IPinfo records

    Returns:
        ThreatScore with final score, verdict, and full evidence.
    """
    weights = config.SIGNAL_WEIGHTS

    # ── Compute sub-scores ───────────────────────────────────────
    ml_score,   ml_ev   = _score_ml(ml)
    auth_score, auth_ev = _score_authentication(auth)
    ip_score,   ip_ev   = _score_ip(ip_intel)
    dom_score,  dom_ev  = _score_domain(domain_intel)
    url_score,  url_ev  = _score_urls(url_analysis, url_sandbox)
    att_score,  att_ev  = _score_attachments(att_analysis, att_content_analysis)

    sub_scores = {
        "ml":             ml_score,
        "authentication": auth_score,
        "ip":             ip_score,
        "domain":         dom_score,
        "url":            url_score,
        "attachment":     att_score,
    }

    # ── Weighted sum ─────────────────────────────────────────────
    raw_score = sum(sub_scores[k] * weights[k] for k in weights)
    final_score = max(0, min(100, int(round(raw_score))))

    verdict = _get_verdict(final_score)

    # ── Separate evidence into negative / positive ────────────────
    all_evidence = ml_ev + auth_ev + ip_ev + dom_ev + url_ev + att_ev
    negative_ev = [e for e in all_evidence if not e.is_positive]
    positive_ev = [e for e in all_evidence if e.is_positive]

    # Sort negative evidence by impact
    impact_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    negative_ev.sort(key=lambda e: impact_order.get(e.impact, 3))

    limitations = _collect_limitations(
        ip_intel=ip_intel,
        url_analysis=url_analysis,
        ml=ml,
        header_intel=header_intel,
        att_content_analysis=att_content_analysis,
        url_sandbox=url_sandbox,
        geo_records=geo_records,
    )

    return ThreatScore(
        threat_score=final_score,
        verdict=verdict,
        sub_scores=sub_scores,
        evidence=negative_ev,
        positive_evidence=positive_ev,
        limitations=limitations,
        weights_used=dict(weights),
    )
