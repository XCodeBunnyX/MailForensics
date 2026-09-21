"""
GmailGuard — Threat Scorer

Combines signals from all analysis modules into an explainable
threat score (0-100).

Design principles:
  - Each available signal produces a sub-score in [0, 100].
  - UNKNOWN / NONE means "insufficient evidence", NOT malicious.
  - Unavailable signals are excluded from the final weighted average.
  - Available signals are re-normalized using their configured weights.
  - LinearSVC decision_function output is treated as a raw discriminant,
    never as a probability.
  - Evidence explains why a score was generated.
  - Positive evidence is surfaced separately.
  - Geolocation contributes forensic context only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any

from . import config
from .authentication_analyzer import AuthResult
from .ip_intelligence import IPIntelligence
from .url_analyzer import URLAnalysis
from .attachment_analyzer import AttachmentAnalysis
from .ml_classifier import MLResult
from .domain_intelligence import DomainIntelligence
from .header_analyzer import HeaderIntelligence


# ────────────────────────────────────────────────────────────────
# DATA CLASSES
# ────────────────────────────────────────────────────────────────

@dataclass
class EvidenceItem:
    """A single piece of forensic evidence contributing to the score."""

    signal: str
    status: str
    impact: str
    explanation: str
    is_positive: bool = False


@dataclass
class ThreatScore:
    """Final combined threat scoring result."""

    threat_score: int
    verdict: str

    # Per-signal sub-scores
    sub_scores: dict[str, int]

    # Evidence
    evidence: list[EvidenceItem]
    positive_evidence: list[EvidenceItem]

    # Limitations / unavailable evidence
    limitations: list[str]

    # Configured weights
    weights_used: dict[str, float]

    # Detailed explainable score breakdown
    score_breakdown: dict[str, Any] = field(default_factory=dict)


# ────────────────────────────────────────────────────────────────
# HELPERS
# ────────────────────────────────────────────────────────────────

def _impact_label(sub_score: int) -> str:
    """Convert a sub-score to an evidence impact label."""

    if sub_score >= config.EVIDENCE_IMPACT_HIGH:
        return "HIGH"

    if sub_score >= config.EVIDENCE_IMPACT_MEDIUM:
        return "MEDIUM"

    return "LOW"


def _get_verdict(score: int) -> str:
    """Convert final numerical score into a verdict."""

    for threshold, label in config.VERDICT_THRESHOLDS:
        if score >= threshold:
            return label

    return "CLEAN"


# ────────────────────────────────────────────────────────────────
# ML / NLP SCORING
# ────────────────────────────────────────────────────────────────

def _score_ml(
    ml: MLResult,
) -> tuple[int, list[EvidenceItem], bool]:
    """
    Score the ML/NLP classifier.

    Returns:
        (sub_score, evidence, available)

    IMPORTANT:
        LinearSVC decision_function() is a raw discriminant.
        It is NOT a probability.

    The raw score is clipped and converted into a bounded
    threat sub-score.
    """

    evidence: list[EvidenceItem] = []

    if not ml.model_available or ml.prediction == "UNKNOWN":
        return 0, [], False

    decision = ml.decision_score

    if ml.prediction == "Phishing":
        if decision is not None:
            clip = config.ML_DECISION_SCORE_CLIP
            clipped = max(0.0, min(clip, decision))
            # Smooth calibrated scaling: from 55 for marginal decisions up to 90 for decisive decisions
            sub_score = int(55 + (clipped / clip) * 35)
            sub_score = min(max(sub_score, 50), 95)
        else:
            sub_score = 65

        evidence.append(
            EvidenceItem(
                signal="ML/NLP",
                status="PHISHING",
                impact=_impact_label(sub_score),
                explanation=(
                    f"Linguistic classifier flagged phishing patterns "
                    f"(decision score: {decision:.3f} — raw discriminant, not a probability). "
                    "Email text matches phishing indicators."
                    if decision is not None
                    else "Linguistic classifier flagged phishing patterns in email text."
                ),
            )
        )

        return sub_score, evidence, True

    # ── Legitimate ──────────────────────────────────────────────

    base = 15

    if decision is not None:
        clip = config.ML_DECISION_SCORE_CLIP
        clipped = max(-clip, min(0.0, decision))
        # Negative SVM score means stronger legitimate evidence.
        extra_reduction = int(
            (-clipped / clip) * 10
        )
        sub_score = max(base - extra_reduction, 5)

    else:
        sub_score = base

    evidence.append(
        EvidenceItem(
            signal="ML/NLP",
            status="LEGITIMATE",
            impact="POSITIVE",
            explanation=(
                "Linguistic classifier evaluated content as normal/legitimate."
            ),
            is_positive=True,
        )
    )

    return sub_score, evidence, True


# ────────────────────────────────────────────────────────────────
# AUTHENTICATION SCORING
# ────────────────────────────────────────────────────────────────

def _score_authentication(
    auth: AuthResult,
) -> tuple[int, list[EvidenceItem], bool]:
    """
    Score SPF / DKIM / DMARC.

    UNKNOWN / NONE / NEUTRAL authentication results are NOT
    treated as malicious and are excluded from the final
    weighted score when no authentication evidence exists.
    """

    evidence: list[EvidenceItem] = []

    results = {
        "SPF": auth.spf,
        "DKIM": auth.dkim,
        "DMARC": auth.dmarc,
    }

    known_results = []

    for proto, result in results.items():

        if result not in ("UNKNOWN", "NONE", "NEUTRAL"):
            known_results.append(result)

        sub = config.AUTH_SCORE_MAP.get(result, 50)

        if result == "PASS":

            evidence.append(
                EvidenceItem(
                    signal=proto,
                    status="PASS",
                    impact="POSITIVE",
                    explanation=(
                        f"{proto} passed. This indicates successful "
                        f"{proto} authentication but does not by itself "
                        "prove that the email is safe."
                    ),
                    is_positive=True,
                )
            )

        elif result in (
            "FAIL",
            "SOFTFAIL",
            "PERMERROR",
            "TEMPERROR",
        ):

            evidence.append(
                EvidenceItem(
                    signal=proto,
                    status=result,
                    impact=_impact_label(sub),
                    explanation=(
                        f"{proto} returned {result}. "
                        "The available authentication result "
                        "indicates an authentication problem."
                    ),
                )
            )

    # No usable authentication result.
    if not known_results:
        return 0, [], False

    # Calculate average authentication risk.
    scores = [
        config.AUTH_SCORE_MAP.get(result, 50)
        for result in known_results
    ]

    return int(round(sum(scores) / len(scores))), evidence, True


# ────────────────────────────────────────────────────────────────
# IP SCORING
# ────────────────────────────────────────────────────────────────

def _score_ip(
    ip_intel: IPIntelligence,
) -> tuple[int, list[EvidenceItem], bool]:

    evidence: list[EvidenceItem] = []

    # No observable IPs = no IP evidence.
    if not ip_intel.records:
        return 0, [], False

    sub_score = ip_intel.max_reputation_score

    for record in ip_intel.records:

        if record.reputation == "malicious":

            evidence.append(
                EvidenceItem(
                    signal="IP Reputation",
                    status="MALICIOUS",
                    impact=_impact_label(record.reputation_score),
                    explanation=(
                        f"Observable relay IP {record.ip} has "
                        f"malicious reputation "
                        f"(categories: {record.categories}, "
                        f"source: {record.source}). "
                        "This represents relay infrastructure and "
                        "not necessarily the sender's physical device."
                    ),
                )
            )

        elif record.reputation == "suspicious":

            evidence.append(
                EvidenceItem(
                    signal="IP Reputation",
                    status="SUSPICIOUS",
                    impact=_impact_label(record.reputation_score),
                    explanation=(
                        f"Observable relay IP {record.ip} has "
                        "suspicious reputation "
                        f"(categories: {record.categories})."
                    ),
                )
            )

        elif record.reputation == "clean":

            evidence.append(
                EvidenceItem(
                    signal="IP Reputation",
                    status="CLEAN",
                    impact="POSITIVE",
                    explanation=(
                        f"Observable relay IP {record.ip} "
                        "has clean reputation."
                    ),
                    is_positive=True,
                )
            )

    return sub_score, evidence, True


# ────────────────────────────────────────────────────────────────
# DOMAIN SCORING
# ────────────────────────────────────────────────────────────────

def _score_domain(
    domain_intel: DomainIntelligence,
) -> tuple[int, list[EvidenceItem], bool]:

    evidence: list[EvidenceItem] = []

    if not domain_intel.domain:
        return 0, [], False

    sub_score = max(
        0,
        min(100, int(domain_intel.risk_score))
    )

    for reason in domain_intel.reasons:

        evidence.append(
            EvidenceItem(
                signal="Domain Intelligence",
                status=domain_intel.reputation.upper(),
                impact=_impact_label(sub_score),
                explanation=reason,
            )
        )

    if (
        not domain_intel.reasons
        and domain_intel.reputation == "clean"
    ):

        evidence.append(
            EvidenceItem(
                signal="Domain Intelligence",
                status="CLEAN",
                impact="POSITIVE",
                explanation=(
                    f"Sender domain '{domain_intel.domain}' "
                    "has clean reputation."
                ),
                is_positive=True,
            )
        )

    return sub_score, evidence, True


# ────────────────────────────────────────────────────────────────
# URL SCORING
# ────────────────────────────────────────────────────────────────

def _score_urls(
    url_analysis: URLAnalysis,
    url_sandbox: Optional[Any] = None,
) -> tuple[int, list[EvidenceItem], bool]:

    evidence: list[EvidenceItem] = []

    has_urls = (
        url_analysis.total_count > 0
        or (
            url_sandbox
            and getattr(url_sandbox, "total_scanned", 0) > 0
        )
    )

    # No URLs = unavailable signal, not a safe signal and not
    # a malicious signal.
    if not has_urls:
        return 0, [], False

    max_url_score = max(
        (f.risk_score for f in url_analysis.findings),
        default=0,
    )

    # ── Static URL evidence ────────────────────────────────────

    for finding in url_analysis.findings:

        if finding.risk_score >= 30:

            evidence.append(
                EvidenceItem(
                    signal="URL Analysis",
                    status=(
                        "SUSPICIOUS"
                        if finding.risk_score < 60
                        else "MALICIOUS"
                    ),
                    impact=_impact_label(finding.risk_score),
                    explanation=(
                        f"URL '{finding.url[:80]}' — "
                        + "; ".join(finding.reasons[:3])
                    ),
                )
            )

    # ── Dynamic sandbox ─────────────────────────────────────────

    if url_sandbox:

        for sf in getattr(url_sandbox, "findings", []):

            if sf.verdict == "MALICIOUS" or sf.is_malicious:

                max_url_score = max(
                    max_url_score,
                    max(sf.malicious_score, 80),
                )

                evidence.append(
                    EvidenceItem(
                        signal="Browser Sandbox",
                        status="MALICIOUS",
                        impact="HIGH",
                        explanation=(
                            f"Browser sandbox dynamic execution flagged "
                            f"URL '{sf.submitted_url[:70]}' as "
                            f"MALICIOUS "
                            f"(score: {sf.malicious_score}/100) — "
                            + "; ".join(sf.reasons[:2])
                        ),
                    )
                )

            elif (
                getattr(sf, "content_category", None)
                == "ADULT_CONTENT"
                or "ADULT_CONTENT_DETECTED"
                in getattr(sf, "behavior_indicators", [])
            ):

                max_url_score = max(max_url_score, 40)

                evidence.append(
                    EvidenceItem(
                        signal="Browser Sandbox",
                        status="SUSPICIOUS",
                        impact="MEDIUM",
                        explanation=(
                            f"Adult content detected on destination "
                            f"URL '{sf.submitted_url[:70]}'. "
                            "This is unwanted/suspicious content, "
                            "not classified as malware (not malware classification)."
                        ),
                    )
                )

            elif (
                sf.verdict == "SUSPICIOUS"
                or (
                    sf.downloads
                    and len(sf.downloads) > 0
                )
            ):

                max_url_score = max(
                    max_url_score,
                    sf.malicious_score if sf.malicious_score > 0 else 35,
                )

                dl_note = (
                    f" Triggered download of "
                    f"{len(sf.downloads)} payload(s)."
                    if sf.downloads
                    else ""
                )

                evidence.append(
                    EvidenceItem(
                        signal="Browser Sandbox",
                        status="SUSPICIOUS",
                        impact="MEDIUM",
                        explanation=(
                            f"Browser sandbox dynamic execution detected "
                            f"suspicious behavior on "
                            f"'{sf.submitted_url[:70]}'."
                            f"{dl_note} "
                            + "; ".join(sf.reasons[:2])
                        ),
                    )
                )

            elif (
                sf.verdict == "CLEAN"
                and not any(
                    e.status in ("SUSPICIOUS", "MALICIOUS")
                    for e in evidence
                )
            ):

                evidence.append(
                    EvidenceItem(
                        signal="Browser Sandbox",
                        status="CLEAN",
                        impact="POSITIVE",
                        explanation=(
                            f"Browser sandbox dynamic execution completed "
                            f"with no threats detected for "
                            f"'{sf.submitted_url[:70]}'."
                        ),
                        is_positive=True,
                    )
                )

    # ── Clean URLs ──────────────────────────────────────────────

    has_negative_ev = any(
        e.status in ("MALICIOUS", "SUSPICIOUS")
        for e in evidence
    )

    if (
        not has_negative_ev
        and url_analysis.suspicious_count == 0
    ):

        if not any(e.is_positive and "URL" in e.signal for e in evidence):
            evidence.append(
                EvidenceItem(
                    signal="URL Analysis",
                    status="CLEAN",
                    impact="POSITIVE",
                    explanation=(
                        f"All {url_analysis.total_count} URL(s) "
                        "passed static and sandbox analysis."
                    ),
                    is_positive=True,
                )
            )

        return max_url_score, evidence, True

    # ── URL score ───────────────────────────────────────────────

    prop = (
        url_analysis.suspicious_count
        / url_analysis.total_count
        if url_analysis.total_count
        else 0.5
    )

    sub_score = (
        int(max_url_score * 0.7 + prop * 30)
        if url_analysis.total_count
        else max_url_score
    )

    if has_negative_ev:
        sub_score = max(sub_score, max_url_score)

    return min(max(sub_score, 0), 100), evidence, True


# ────────────────────────────────────────────────────────────────
# ATTACHMENT SCORING
# ────────────────────────────────────────────────────────────────

def _score_attachments(
    att_analysis: AttachmentAnalysis,
    att_content_analysis: Optional[Any] = None,
) -> tuple[int, list[EvidenceItem], bool]:

    evidence: list[EvidenceItem] = []

    # No attachment = unavailable signal.
    if att_analysis.total_count == 0:
        return 0, [], False

    max_score = max(
        (f.risk_score for f in att_analysis.findings),
        default=0,
    )

    for finding in att_analysis.findings:

        if finding.risk_score >= 30:

            evidence.append(
                EvidenceItem(
                    signal="Attachment Analysis",
                    status="SUSPICIOUS",
                    impact=_impact_label(finding.risk_score),
                    explanation=(
                        f"Attachment '{finding.filename}' — "
                        + "; ".join(finding.reasons[:3])
                    ),
                )
            )

    # ── Deep attachment analysis ────────────────────────────────

    if att_content_analysis:

        for cf in getattr(
            att_content_analysis,
            "findings",
            [],
        ):

            if cf.encrypted:

                evidence.append(
                    EvidenceItem(
                        signal="Attachment Content",
                        status="LIMITED",
                        impact="MEDIUM",
                        explanation=(
                            f"Attachment '{cf.filename}' is "
                            "password protected / encrypted. "
                            "Content could not be fully verified."
                        ),
                    )
                )

            elif cf.content_analysis_status == "ANALYZED":

                if cf.javascript_detected:

                    max_score = max(max_score, 80)

                    evidence.append(
                        EvidenceItem(
                            signal="Attachment Content",
                            status="DANGEROUS",
                            impact="HIGH",
                            explanation=(
                                f"Attachment '{cf.filename}' contains "
                                "embedded JavaScript code or script tokens."
                            ),
                        )
                    )

                if "/Launch" in cf.actions_detected:

                    max_score = max(max_score, 85)

                    evidence.append(
                        EvidenceItem(
                            signal="Attachment Content",
                            status="DANGEROUS",
                            impact="HIGH",
                            explanation=(
                                f"Attachment '{cf.filename}' contains "
                                "a /Launch action capable of executing "
                                "external commands."
                            ),
                        )
                    )

                elif "/OpenAction" in cf.actions_detected:

                    max_score = max(max_score, 60)

                    evidence.append(
                        EvidenceItem(
                            signal="Attachment Content",
                            status="SUSPICIOUS",
                            impact="MEDIUM",
                            explanation=(
                                f"Attachment '{cf.filename}' contains "
                                "an automated /OpenAction execution trigger."
                            ),
                        )
                    )

                if cf.embedded_files:

                    max_score = max(max_score, 75)

                    evidence.append(
                        EvidenceItem(
                            signal="Attachment Content",
                            status="SUSPICIOUS",
                            impact="HIGH",
                            explanation=(
                                f"Attachment '{cf.filename}' contains "
                                "embedded internal file payloads."
                            ),
                        )
                    )

            if (
                cf.content_risk_score >= 30
                and not any(
                    e.signal == "Attachment Content"
                    and cf.filename in e.explanation
                    for e in evidence
                )
            ):

                evidence.append(
                    EvidenceItem(
                        signal="Attachment Content",
                        status=(
                            "DANGEROUS"
                            if cf.content_risk_score >= 60
                            else "SUSPICIOUS"
                        ),
                        impact=(
                            "HIGH"
                            if cf.content_risk_score >= 60
                            else "MEDIUM"
                        ),
                        explanation=(
                            f"Attachment '{cf.filename}' contains "
                            "suspicious/high-risk content or embedded "
                            f"URLs "
                            f"(Verdict: {cf.content_verdict}, "
                            f"Risk Score: {cf.content_risk_score}/100) — "
                            + "; ".join(cf.reasons[:2])
                        ),
                    )
                )

            if cf.content_risk_score > max_score:
                max_score = cf.content_risk_score

    # ── Unverified attachments ─────────────────────────────────

    has_unverified = False

    if att_content_analysis:

        for cf in getattr(
            att_content_analysis,
            "findings",
            [],
        ):

            if (
                cf.encrypted
                or cf.content_analysis_status
                in ("LIMITED", "FAILED", "UNSUPPORTED")
                or cf.content_verdict
                in ("NOT_ANALYZABLE", "UNKNOWN")
            ):

                has_unverified = True
                break

    # ── Clean attachment ────────────────────────────────────────

    if (
        not evidence
        and att_analysis.suspicious_count == 0
    ):

        if has_unverified:

            evidence.append(
                EvidenceItem(
                    signal="Attachment Analysis",
                    status="NOT_ANALYZABLE",
                    impact="MEDIUM",
                    explanation=(
                        "Attachment contains encrypted, limited, "
                        "or unanalyzable files; contents could not "
                        "be fully verified."
                    ),
                )
            )

            return max(35, max_score), evidence, True

        evidence.append(
            EvidenceItem(
                signal="Attachment Analysis",
                status="NO_THREATS_DETECTED",
                impact="POSITIVE",
                explanation=(
                    "No suspicious attachment characteristics or "
                    "dangerous content detected."
                ),
                is_positive=True,
            )
        )

        return 10, evidence, True

    return min(max_score, 100), evidence, True


# ────────────────────────────────────────────────────────────────
# LIMITATIONS
# ────────────────────────────────────────────────────────────────

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

    limitations.extend(header_intel.warnings)

    # Attachment limitations
    if att_content_analysis:

        for cf in getattr(
            att_content_analysis,
            "findings",
            [],
        ):

            if cf.encrypted:

                limitations.append(
                    f"Attachment '{cf.filename}' is password "
                    "protected; content analysis was limited."
                )

            elif cf.content_analysis_status == "FAILED":

                limitations.append(
                    f"Attachment '{cf.filename}' content parsing "
                    f"encountered an error: "
                    f"{cf.reason or 'malformed'}"
                )

    # URL sandbox limitations
    if url_sandbox:

        limitations.extend(
            getattr(
                url_sandbox,
                "limitations",
                [],
            )
        )

        for sf in getattr(
            url_sandbox,
            "findings",
            [],
        ):

            if sf.status in (
                "ERROR",
                "TIMEOUT",
                "FAILED",
            ):

                limitations.append(
                    f"urlscan.io sandbox for "
                    f"'{sf.submitted_url[:50]}': "
                    f"Status {sf.status} "
                    f"(Reason: "
                    f"{sf.error or 'analysis incomplete'})"
                )

            elif (
                sf.verdict == "UNKNOWN"
                and getattr(sf, "mode", "") == "MOCK"
            ):

                limitations.append(
                    f"urlscan.io sandbox for "
                    f"'{sf.submitted_url[:50]}': "
                    "Mock mode; live analysis not executed."
                )

    # Geolocation limitations
    if geo_records:

        for g in geo_records:

            status = getattr(
                g,
                "status",
                "success",
            )

            if status in (
                "error",
                "unavailable",
                "not_found",
            ):

                reason = getattr(
                    g,
                    "reason",
                    "no intelligence returned",
                )

                limitations.append(
                    f"IPinfo observable infrastructure for "
                    f"{g.ip}: Status {status.upper()} "
                    f"(Reason: {reason})"
                )

    return limitations


# ────────────────────────────────────────────────────────────────
# MAIN SCORING FUNCTION
# ────────────────────────────────────────────────────────────────

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
    Compute an explainable 0–100 threat score.

    IMPORTANT:
        Only signals for which meaningful evidence exists are included
        in the final weighted average.

        Example:

            ML available
            Domain available
            SPF/DKIM/DMARC UNKNOWN
            No observable IP
            No URL
            No attachment

        → ML and Domain retain their configured relative importance.
        → Missing signals do not artificially dilute the result.
    """

    weights = config.SIGNAL_WEIGHTS

    # ── Compute sub-scores ──────────────────────────────────────

    ml_score, ml_ev, ml_available = _score_ml(ml)

    auth_score, auth_ev, auth_available = (
        _score_authentication(auth)
    )

    ip_score, ip_ev, ip_available = _score_ip(
        ip_intel
    )

    dom_score, dom_ev, dom_available = _score_domain(
        domain_intel
    )

    url_score, url_ev, url_available = _score_urls(
        url_analysis,
        url_sandbox,
    )

    att_score, att_ev, att_available = _score_attachments(
        att_analysis,
        att_content_analysis,
    )

    sub_scores = {
        "ml": ml_score,
        "authentication": auth_score,
        "ip": ip_score,
        "domain": dom_score,
        "url": url_score,
        "attachment": att_score,
    }

    availability = {
        "ml": ml_available,
        "authentication": auth_available,
        "ip": ip_available,
        "domain": dom_available,
        "url": url_available,
        "attachment": att_available,
    }

    # ────────────────────────────────────────────────────────────
    # RISK ACCUMULATION & BOOSTING MODEL
    # ────────────────────────────────────────────────────────────
    # Stage 1: Base score from primary content signals (ML, Domain, IP, Auth)
    # Stage 2: Add URL risk on top as additive boost (never dilutes)
    # Stage 3: Add Attachment risk on top as additive boost (never dilutes)
    # Stage 4: Single-payload severity floor (malicious URL/attachment override)
    # Stage 5: Corroboration multiplier (rewards multiple independent threat vectors)
    # Stage 6: Final score bounding [0, 100] and verdict determination
    # ────────────────────────────────────────────────────────────

    primary_weights = getattr(config, "PRIMARY_SIGNAL_WEIGHTS", {
        "ml":             0.75,
        "domain":         0.15,
        "authentication": 0.10,
        "ip":             0.10,
    })
    boost_cfg = getattr(config, "PAYLOAD_BOOST_CONFIG", {
        "url_max_boost":        25.0,
        "att_max_boost":        25.0,
        "clean_threshold":      20.0,
        "suspicious_threshold": 40.0,
        "malicious_threshold":  70.0,
        "corroboration_3_plus": 1.06,
    })

    # ── STAGE 1: Base Score from Primary Content Signals ────────
    # Primary signals represent intrinsic message identity & content:
    # ml (linguistic phishing detection), domain (sender domain reputation/typosquatting),
    # auth (SPF/DKIM/DMARC), and ip (relay reputation).
    primary_available_weight = sum(
        primary_weights[k]
        for k in primary_weights
        if availability.get(k, False)
    )

    if primary_available_weight > 0:
        base_score = sum(
            sub_scores[k] * primary_weights[k]
            for k in primary_weights
            if availability.get(k, False)
        ) / primary_available_weight
    else:
        base_score = 0.0

    # ── STAGE 2: Add URL Risk On Top (Additive Boost) ───────────
    # A clean or absent URL contributes 0 bonus risk and never dilutes the base score.
    # A suspicious or malicious URL adds direct risk points.
    url_boost = 0.0
    if url_available:
        clean_th = boost_cfg.get("clean_threshold", 20.0)
        url_max = boost_cfg.get("url_max_boost", 30.0)
        if url_score > clean_th:
            url_fraction = (url_score - clean_th) / (100.0 - clean_th)
            url_boost = url_fraction * url_max

    # ── STAGE 3: Add Attachment Risk On Top (Additive Boost) ────
    # A clean or absent attachment contributes 0 bonus risk.
    # Dangerous extensions, macros, or malicious payloads add direct risk points.
    att_boost = 0.0
    if att_available:
        clean_th = boost_cfg.get("clean_threshold", 20.0)
        att_max = boost_cfg.get("att_max_boost", 30.0)
        if att_score > clean_th:
            att_fraction = (att_score - clean_th) / (100.0 - clean_th)
            att_boost = att_fraction * att_max

    # ── STAGE 4: Single-Payload Severity Floor ──────────────────
    # If a URL or attachment independently has high/critical risk (e.g. sandbox/phishtank/malware),
    # the threat score must not fall below that payload's critical severity.
    accumulated_score = base_score + url_boost + att_boost
    payload_floor = 0.0
    if url_available and url_score >= 70:
        payload_floor = max(payload_floor, float(url_score))
    if att_available and att_score >= 70:
        payload_floor = max(payload_floor, float(att_score))

    accumulated_score = max(accumulated_score, payload_floor)

    # ── STAGE 5: Corroboration Multiplier ───────────────────────
    # Reward multiple independent risk indicators that corroborate a threat.
    risky_channels = 0
    if ml_available and ml_score >= 60:
        risky_channels += 1
    if auth_available and auth_score >= 60:
        risky_channels += 1
    if dom_available and dom_score >= 40:
        risky_channels += 1
    if ip_available and ip_score >= 50:
        risky_channels += 1
    if url_available and url_score >= 40:
        risky_channels += 1
    if att_available and att_score >= 40:
        risky_channels += 1

    corrob_multiplier = 1.0
    if risky_channels >= 3:
        corrob_multiplier = boost_cfg.get("corroboration_3_plus", 1.06)

    if accumulated_score > 25:
        accumulated_score *= corrob_multiplier

    # ── STAGE 6: Bounding & Verdict ─────────────────────────────
    final_score = max(0, min(100, int(round(accumulated_score))))
    verdict = _get_verdict(final_score)

    # ── STAGE 7: Explainable Component Breakdown ────────────────
    breakdown_components = []

    # 1. ML
    ml_contrib = (
        (sub_scores["ml"] * primary_weights["ml"] / primary_available_weight)
        if (primary_available_weight > 0 and availability.get("ml"))
        else 0.0
    )
    ml_reason = (
        f"Linguistic classifier flagged phishing patterns (decision score: {ml.decision_score:.2f})"
        if (availability.get("ml") and ml.prediction == "Phishing")
        else (
            "Linguistic classifier evaluated content as normal / legitimate"
            if availability.get("ml")
            else "Model not available"
        )
    )
    breakdown_components.append({
        "signal": "ml",
        "name": "Email Content ML",
        "sub_score": sub_scores["ml"],
        "contribution": round(ml_contrib, 1),
        "available": availability.get("ml", False),
        "reason": ml_reason,
    })

    # 2. Domain
    dom_contrib = (
        (sub_scores["domain"] * primary_weights["domain"] / primary_available_weight)
        if (primary_available_weight > 0 and availability.get("domain"))
        else 0.0
    )
    dom_reason = (
        "; ".join(domain_intel.reasons[:2])
        if domain_intel.reasons
        else (
            f"Sender domain '{domain_intel.domain}' reputation clean"
            if domain_intel.domain
            else "No sender domain"
        )
    )
    breakdown_components.append({
        "signal": "domain",
        "name": "Sender Domain",
        "sub_score": sub_scores["domain"],
        "contribution": round(dom_contrib, 1),
        "available": availability.get("domain", False),
        "reason": dom_reason,
    })

    # 3. Authentication
    auth_contrib = (
        (sub_scores["authentication"] * primary_weights["authentication"] / primary_available_weight)
        if (primary_available_weight > 0 and availability.get("authentication"))
        else 0.0
    )
    auth_reason = (
        auth.summary or "SPF/DKIM/DMARC authentication evaluated"
        if availability.get("authentication")
        else "Authentication headers not available in email"
    )
    breakdown_components.append({
        "signal": "authentication",
        "name": "Email Authentication",
        "sub_score": sub_scores["authentication"],
        "contribution": round(auth_contrib, 1),
        "available": availability.get("authentication", False),
        "reason": auth_reason,
    })

    # 4. IP
    ip_contrib = (
        (sub_scores["ip"] * primary_weights["ip"] / primary_available_weight)
        if (primary_available_weight > 0 and availability.get("ip"))
        else 0.0
    )
    ip_reason = (
        f"Relay infrastructure reputation evaluated ({len(ip_intel.records)} IPs)"
        if availability.get("ip")
        else "No observable public relay IP"
    )
    breakdown_components.append({
        "signal": "ip",
        "name": "Relay Infrastructure",
        "sub_score": sub_scores["ip"],
        "contribution": round(ip_contrib, 1),
        "available": availability.get("ip", False),
        "reason": ip_reason,
    })

    # 5. URL
    url_reason = (
        f"URL dynamic analysis detected threat indicators (risk score: {url_score})"
        if url_boost > 0
        else (
            "Extracted URLs verified clean with no threats in browser sandbox"
            if availability.get("url")
            else "No URLs present in email"
        )
    )
    breakdown_components.append({
        "signal": "url",
        "name": "URL Security",
        "sub_score": sub_scores["url"],
        "contribution": round(url_boost, 1),
        "available": availability.get("url", False),
        "reason": url_reason,
    })

    # 6. Attachment
    att_reason = (
        f"Dangerous attachment characteristics or payloads detected (risk score: {att_score})"
        if att_boost > 0
        else (
            "Attachments inspected statically with no threats detected"
            if availability.get("attachment")
            else "No attachments present"
        )
    )
    breakdown_components.append({
        "signal": "attachment",
        "name": "Attachment Security",
        "sub_score": sub_scores["attachment"],
        "contribution": round(att_boost, 1),
        "available": availability.get("attachment", False),
        "reason": att_reason,
    })

    score_breakdown = {
        "base_score": round(base_score, 1),
        "url_boost": round(url_boost, 1),
        "attachment_boost": round(att_boost, 1),
        "corroboration_multiplier": round(corrob_multiplier, 2),
        "final_score": final_score,
        "verdict": verdict,
        "components": breakdown_components,
    }

    # ────────────────────────────────────────────────────────────
    # DEBUG OUTPUT
    # ────────────────────────────────────────────────────────────

    print("\n========== GMAILGUARD THREAT SCORE DEBUG ==========")
    print(f"ML:                 {ml_score}")
    print(f"Authentication:     {auth_score} | available={auth_available}")
    print(f"IP:                 {ip_score} | available={ip_available}")
    print(f"Domain:             {dom_score} | available={dom_available}")
    print(f"URL:                {url_score} | available={url_available} (boost: +{url_boost:.1f})")
    print(f"Attachment:         {att_score} | available={att_available} (boost: +{att_boost:.1f})")
    print(f"Base Score:         {base_score:.2f}")
    print(f"Risky Channels:     {risky_channels} (multiplier: {corrob_multiplier:.2f}x)")
    print(f"Accumulated Score:  {accumulated_score:.2f}")
    print(f"Final score:        {final_score}")
    print(f"Verdict:            {verdict}")
    print("==================================================\n")

    # ────────────────────────────────────────────────────────────
    # EVIDENCE
    # ────────────────────────────────────────────────────────────

    all_evidence = (
        ml_ev
        + auth_ev
        + ip_ev
        + dom_ev
        + url_ev
        + att_ev
    )

    negative_ev = [
        e
        for e in all_evidence
        if not e.is_positive
    ]

    positive_ev = [
        e
        for e in all_evidence
        if e.is_positive
    ]

    impact_order = {
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 2,
    }

    negative_ev.sort(
        key=lambda e: impact_order.get(
            e.impact,
            3,
        )
    )

    # ────────────────────────────────────────────────────────────
    # LIMITATIONS
    # ────────────────────────────────────────────────────────────

    limitations = _collect_limitations(
        ip_intel=ip_intel,
        url_analysis=url_analysis,
        ml=ml,
        header_intel=header_intel,
        att_content_analysis=att_content_analysis,
        url_sandbox=url_sandbox,
        geo_records=geo_records,
    )

    # Explicitly record unavailable security evidence.
    if not auth_available:
        limitations.append(
            "SPF/DKIM/DMARC results were unavailable or "
            "not present in the supplied email headers."
        )

    if not ip_available:
        limitations.append(
            "No observable public relay IP was available "
            "for IP reputation analysis."
        )

    if not url_available:
        limitations.append(
            "No URLs were available for URL threat analysis."
        )

    if not att_available:
        limitations.append(
            "No attachments were available for attachment analysis."
        )

    return ThreatScore(
        threat_score=final_score,
        verdict=verdict,
        sub_scores=sub_scores,
        evidence=negative_ev,
        positive_evidence=positive_ev,
        limitations=limitations,
        weights_used=dict(weights),
        score_breakdown=score_breakdown,
    )