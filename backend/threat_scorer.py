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

import config
from authentication_analyzer import AuthResult
from ip_intelligence import IPIntelligence
from url_analyzer import URLAnalysis
from attachment_analyzer import AttachmentAnalysis
from ml_classifier import MLResult
from domain_intelligence import DomainIntelligence
from header_analyzer import HeaderIntelligence


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


def _score_urls(url_analysis: URLAnalysis) -> tuple[int, list[EvidenceItem]]:
    """Compute sub-score from URL analysis."""
    evidence: list[EvidenceItem] = []

    if url_analysis.total_count == 0:
        return 10, []   # no URLs → low risk contribution

    if url_analysis.suspicious_count == 0:
        evidence.append(EvidenceItem(
            signal="URL Analysis",
            status="CLEAN",
            impact="POSITIVE",
            explanation=f"All {url_analysis.total_count} URL(s) passed static analysis.",
            is_positive=True,
        ))
        return 10, evidence

    # Score based on worst URL + proportion suspicious
    max_url_score = max((f.risk_score for f in url_analysis.findings), default=0)
    proportion = url_analysis.suspicious_count / url_analysis.total_count
    sub_score = int(max_url_score * 0.7 + proportion * 30)

    for finding in url_analysis.findings:
        if finding.risk_score >= 30:
            evidence.append(EvidenceItem(
                signal="URL Analysis",
                status="SUSPICIOUS",
                impact=_impact_label(finding.risk_score),
                explanation=(
                    f"URL '{finding.url[:80]}' — "
                    + "; ".join(finding.reasons[:3])
                ),
            ))

    return min(sub_score, 100), evidence


def _score_attachments(att_analysis: AttachmentAnalysis) -> tuple[int, list[EvidenceItem]]:
    """Compute sub-score from attachment analysis."""
    evidence: list[EvidenceItem] = []

    if att_analysis.total_count == 0:
        return 0, []   # no attachments → zero contribution

    if att_analysis.suspicious_count == 0:
        evidence.append(EvidenceItem(
            signal="Attachment Analysis",
            status="CLEAN",
            impact="POSITIVE",
            explanation="No suspicious attachment characteristics found.",
            is_positive=True,
        ))
        return 10, evidence

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

    return min(max_score, 100), evidence


def _collect_limitations(
    ip_intel: IPIntelligence,
    url_analysis: URLAnalysis,
    ml: MLResult,
    header_intel: HeaderIntelligence,
) -> list[str]:
    limitations: list[str] = []
    limitations.extend(ip_intel.limitations)
    limitations.extend(url_analysis.limitations)
    if not ml.model_available:
        limitations.append(ml.note)
    for warn in header_intel.warnings:
        limitations.append(warn)
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

    Returns:
        ThreatScore with final score, verdict, and full evidence.
    """
    weights = config.SIGNAL_WEIGHTS

    # ── Compute sub-scores ───────────────────────────────────────
    ml_score,   ml_ev   = _score_ml(ml)
    auth_score, auth_ev = _score_authentication(auth)
    ip_score,   ip_ev   = _score_ip(ip_intel)
    dom_score,  dom_ev  = _score_domain(domain_intel)
    url_score,  url_ev  = _score_urls(url_analysis)
    att_score,  att_ev  = _score_attachments(att_analysis)

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

    limitations = _collect_limitations(ip_intel, url_analysis, ml, header_intel)

    return ThreatScore(
        threat_score=final_score,
        verdict=verdict,
        sub_scores=sub_scores,
        evidence=negative_ev,
        positive_evidence=positive_ev,
        limitations=limitations,
        weights_used=dict(weights),
    )
