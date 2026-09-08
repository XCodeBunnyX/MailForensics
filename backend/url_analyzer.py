"""
GmailGuard — URL Analyzer

Extracts URLs from email body (plain text and HTML) and performs
STATIC feature analysis to identify suspicious characteristics.

Rules:
  - URLs are NEVER visited or resolved.
  - Domain reputation can be plugged in via mock_data/domain_reputation.py.
  - No HTTP requests are made to extracted URLs.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser

from . import config
from .mock_data.domain_reputation import get_domain_reputation


# ── URL extraction regexes ───────────────────────────────────────
_URL_REGEX = re.compile(
    r'https?://[^\s\'"<>\[\](){}|\\^`]+'
    r'|'
    r'www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s\'"<>\[\](){}|\\^`]*',
    re.IGNORECASE,
)

_IP_URL_REGEX = re.compile(
    r'https?://(\d{1,3}\.){3}\d{1,3}',
    re.IGNORECASE,
)


class _HrefExtractor(HTMLParser):
    """Extract href URLs and display text from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []   # (href, display_text)
        self._current_href: str = ""
        self._current_text: list[str] = []
        self._in_anchor: bool = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag.lower() == "a":
            self._in_anchor = True
            self._current_href = ""
            self._current_text = []
            attr_dict = dict(attrs)
            self._current_href = attr_dict.get("href", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._in_anchor:
            display = "".join(self._current_text).strip()
            if self._current_href:
                self.links.append((self._current_href, display))
            self._in_anchor = False

    def handle_data(self, data: str) -> None:
        if self._in_anchor:
            self._current_text.append(data)


def _extract_domain(url: str) -> str:
    """Extract the netloc/domain from a URL string."""
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        return parsed.netloc.lower().split(":")[0]  # strip port
    except Exception:
        return ""


def _get_tld(domain: str) -> str:
    """Return the TLD including the dot (e.g. '.com')."""
    parts = domain.rsplit(".", 1)
    return "." + parts[-1].lower() if len(parts) > 1 else ""


def _count_subdomains(domain: str) -> int:
    """Count the number of subdomains (dots minus 1 for apex)."""
    return max(domain.count(".") - 1, 0)


def _has_suspicious_chars(url: str) -> list[str]:
    """Return list of suspicious character/pattern matches found in URL path."""
    found = []
    path = url.split("?")[0]   # check path, not query string
    for pattern in config.SUSPICIOUS_CHAR_PATTERNS:
        if pattern in path:
            found.append(pattern)
    return found


@dataclass
class URLFinding:
    """Analysis result for a single URL."""
    url: str
    domain: str
    tld: str
    risk_score: int          # 0-100 for this URL

    # Feature flags
    is_ip_url: bool
    is_url_shortener: bool
    has_suspicious_tld: bool
    excessive_subdomains: bool
    has_suspicious_chars: bool
    suspicious_char_matches: list[str]
    uses_https: bool
    display_href_mismatch: bool  # displayed text looks like URL but ≠ href
    domain_reputation: str       # clean / suspicious / malicious / unknown
    domain_rep_score: int        # 0-100

    reasons: list[str]           # human-readable risk reasons


@dataclass
class URLAnalysis:
    """Aggregated URL analysis result."""
    total_count: int
    suspicious_count: int
    findings: list[URLFinding]
    all_urls: list[str]          # de-duplicated list of all extracted URLs
    limitations: list[str]


def _analyze_single_url(
    url: str,
    display_text: str = "",
) -> URLFinding:
    """Analyze a single URL and compute a risk score."""
    reasons: list[str] = []
    score = 0

    domain = _extract_domain(url)
    tld = _get_tld(domain)
    uses_https = url.lower().startswith("https://")

    # Feature checks
    is_ip_url = bool(_IP_URL_REGEX.match(url))
    if is_ip_url:
        score += 30
        reasons.append("IP address used directly as URL (bypasses domain reputation).")

    is_shortener = domain in config.URL_SHORTENERS
    if is_shortener:
        score += 25
        reasons.append(f"URL shortener detected ({domain}): hides true destination.")

    has_susp_tld = tld in config.SUSPICIOUS_TLDS
    if has_susp_tld:
        score += 20
        reasons.append(f"Suspicious TLD '{tld}' commonly abused in phishing.")

    subdomain_count = _count_subdomains(domain)
    excessive_subs = subdomain_count >= config.MAX_SUBDOMAINS_ALLOWED
    if excessive_subs:
        score += 15
        reasons.append(
            f"Excessive subdomains ({subdomain_count}) — "
            "may attempt to disguise malicious domain."
        )

    susp_chars = _has_suspicious_chars(url)
    has_susp_chars = bool(susp_chars)
    if has_susp_chars:
        score += 15
        reasons.append(f"Suspicious characters in URL path: {susp_chars}.")

    if not uses_https:
        score += 10
        reasons.append("URL uses HTTP (not HTTPS) — traffic is unencrypted.")

    # Display text vs href mismatch
    mismatch = False
    if display_text:
        # If display text looks like a URL and differs from actual href domain
        dt_lower = display_text.lower().strip()
        if re.match(r'https?://', dt_lower) or dt_lower.startswith("www."):
            dt_domain = _extract_domain(display_text)
            if dt_domain and dt_domain != domain:
                mismatch = True
                score += 20
                reasons.append(
                    f"Display text '{display_text}' suggests a different domain "
                    f"than actual href domain '{domain}' — classic phishing."
                )

    # Domain reputation
    rep = get_domain_reputation(domain)
    dom_rep = rep["reputation"]
    dom_rep_score = rep["score"]
    if dom_rep == "malicious":
        score += 30
        reasons.append(f"Domain '{domain}' has malicious reputation ({rep['source']}).")
    elif dom_rep == "suspicious":
        score += 15
        reasons.append(f"Domain '{domain}' has suspicious reputation ({rep['source']}).")

    risk_score = min(score, 100)

    return URLFinding(
        url=url,
        domain=domain,
        tld=tld,
        risk_score=risk_score,
        is_ip_url=is_ip_url,
        is_url_shortener=is_shortener,
        has_suspicious_tld=has_susp_tld,
        excessive_subdomains=excessive_subs,
        has_suspicious_chars=has_susp_chars,
        suspicious_char_matches=susp_chars,
        uses_https=uses_https,
        display_href_mismatch=mismatch,
        domain_reputation=dom_rep,
        domain_rep_score=dom_rep_score,
        reasons=reasons,
    )


def analyze_urls(text_body: str, html_body: str) -> URLAnalysis:
    """
    Extract and analyze all URLs from email body text and HTML.

    Args:
        text_body: Plain-text body of the email.
        html_body: HTML body of the email.

    Returns:
        URLAnalysis with per-URL findings and aggregate stats.
    """
    limitations: list[str] = [
        "URLs are analyzed by static features only — no HTTP requests are made.",
        "URL shorteners hide the true destination; only the shortener domain is analyzed.",
    ]

    seen: set[str] = set()
    url_display_pairs: list[tuple[str, str]] = []  # (url, display_text)

    # ── Extract from plain text ──────────────────────────────────
    for m in _URL_REGEX.finditer(text_body or ""):
        url = m.group(0).rstrip(".,;:)'\"")
        if url not in seen:
            seen.add(url)
            url_display_pairs.append((url, ""))

    # ── Extract from HTML ────────────────────────────────────────
    if html_body:
        parser = _HrefExtractor()
        try:
            parser.feed(html_body)
        except Exception:
            limitations.append("HTML parsing encountered an error; some URLs may be missed.")

        for href, display in parser.links:
            if href and not href.startswith("mailto:"):
                url = href.rstrip(".,;:)'\"")
                if url not in seen:
                    seen.add(url)
                    url_display_pairs.append((url, display))

        # Also scan raw HTML text for URLs
        for m in _URL_REGEX.finditer(html_body):
            url = m.group(0).rstrip(".,;:)'\"")
            if url not in seen:
                seen.add(url)
                url_display_pairs.append((url, ""))

    if not url_display_pairs:
        return URLAnalysis(
            total_count=0, suspicious_count=0, findings=[],
            all_urls=[], limitations=limitations,
        )

    findings: list[URLFinding] = []
    for url, display in url_display_pairs:
        finding = _analyze_single_url(url, display)
        findings.append(finding)

    # Sort by risk descending
    findings.sort(key=lambda f: f.risk_score, reverse=True)

    suspicious_count = sum(1 for f in findings if f.risk_score >= 30)

    return URLAnalysis(
        total_count=len(findings),
        suspicious_count=suspicious_count,
        findings=findings,
        all_urls=list(seen),
        limitations=limitations,
    )
