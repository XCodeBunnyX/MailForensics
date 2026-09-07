"""
GmailGuard — Domain Intelligence Analyzer

Analyzes sender domain and domains found in the email for:
  - Domain reputation (via mock/live provider)
  - Suspicious TLD
  - Domain age
  - Typosquatting indicators (basic Levenshtein distance check)

This is a standalone module; domain analysis for URLs is handled
in url_analyzer.py using the same mock_data backend.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import config
from mock_data.domain_reputation import get_domain_reputation


# ── Well-known legitimate domains for typosquat comparison ───────
_TRUSTED_DOMAINS: list[str] = [
    "hdfcbank.com", "sbi.co.in", "icicibank.com", "axisbank.com",
    "paypal.com", "amazon.com", "amazon.in", "microsoft.com",
    "google.com", "apple.com", "linkedin.com", "facebook.com",
    "twitter.com", "instagram.com", "netflix.com",
]


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = i
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr = min(dp[j] + 1, prev + 1, dp[j - 1] + cost)
            dp[j - 1] = prev
            prev = curr
        dp[n] = prev
    return dp[n]


def _check_typosquat(domain: str) -> tuple[bool, str]:
    """
    Check if domain looks like a typosquat of a trusted domain.
    Returns (is_typosquat, closest_trusted_domain).
    Threshold: edit distance ≤ 3 and not identical.
    """
    apex = domain.split(".")[-2] + "." + domain.split(".")[-1] if domain.count(".") >= 1 else domain
    for trusted in _TRUSTED_DOMAINS:
        dist = _levenshtein(apex.lower(), trusted.lower())
        if 0 < dist <= 3:
            return True, trusted
    return False, ""


@dataclass
class DomainIntelligence:
    """Domain intelligence result for the sender's domain."""
    domain: str
    reputation: str           # clean / suspicious / malicious / unknown
    reputation_score: int     # 0-100
    categories: list[str]
    age_days: int | None
    registrar: str | None
    virustotal_flags: int | None
    is_suspicious_tld: bool
    tld: str
    is_typosquat: bool
    typosquat_target: str     # which trusted domain it resembles
    risk_score: int           # 0-100 composite for this signal
    reasons: list[str]
    source: str


def analyze_domain(sender_domain: str) -> DomainIntelligence:
    """
    Analyze the sender's domain for reputation and risk indicators.

    Args:
        sender_domain: The domain portion of the From address.

    Returns:
        DomainIntelligence with reputation, typosquat check, and risk score.
    """
    reasons: list[str] = []
    score = 0

    domain = sender_domain.lower().strip()
    tld = ("." + domain.rsplit(".", 1)[-1]) if "." in domain else ""

    if not domain:
        return DomainIntelligence(
            domain="", reputation="UNKNOWN", reputation_score=50,
            categories=[], age_days=None, registrar=None,
            virustotal_flags=None, is_suspicious_tld=False, tld="",
            is_typosquat=False, typosquat_target="", risk_score=50,
            reasons=["Sender domain could not be extracted."], source="",
        )

    # ── Reputation lookup ────────────────────────────────────────
    rep = get_domain_reputation(domain)
    reputation = rep["reputation"]
    rep_score = rep["score"]

    if reputation == "malicious":
        score += 50
        reasons.append(
            f"Domain '{domain}' has malicious reputation "
            f"(categories: {rep['categories']}, source: {rep['source']})."
        )
    elif reputation == "suspicious":
        score += 25
        reasons.append(
            f"Domain '{domain}' has suspicious reputation "
            f"(categories: {rep['categories']}, source: {rep['source']})."
        )

    # ── Domain age ───────────────────────────────────────────────
    age_days = rep.get("age_days")
    if age_days is not None and age_days < 30:
        score += 20
        reasons.append(
            f"Domain '{domain}' is very new ({age_days} days old) — "
            "recently registered domains are commonly used in phishing."
        )
    elif age_days is not None and age_days < 90:
        score += 10
        reasons.append(
            f"Domain '{domain}' is relatively new ({age_days} days old)."
        )

    # ── Suspicious TLD ───────────────────────────────────────────
    is_susp_tld = tld in config.SUSPICIOUS_TLDS
    if is_susp_tld:
        score += 15
        reasons.append(
            f"Sender domain uses suspicious TLD '{tld}' commonly abused in phishing."
        )

    # ── Typosquat check ──────────────────────────────────────────
    is_typo, typo_target = _check_typosquat(domain)
    if is_typo:
        score += 20
        reasons.append(
            f"Domain '{domain}' resembles trusted domain '{typo_target}' "
            "(possible typosquatting / brand impersonation)."
        )

    return DomainIntelligence(
        domain=domain,
        reputation=reputation,
        reputation_score=rep_score,
        categories=rep.get("categories", []),
        age_days=age_days,
        registrar=rep.get("registrar"),
        virustotal_flags=rep.get("virustotal_flags"),
        is_suspicious_tld=is_susp_tld,
        tld=tld,
        is_typosquat=is_typo,
        typosquat_target=typo_target,
        risk_score=min(score, 100),
        reasons=reasons,
        source=rep.get("source", ""),
    )
