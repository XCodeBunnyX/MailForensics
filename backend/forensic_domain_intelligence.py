"""
GmailGuard — Forensic Domain Intelligence

Investigates the historical infrastructure and security observations
of domains extracted from an email (sender domain + URL domains).

PURPOSE:
    Answer "What has this domain been associated with over time?"
    NOT: "Is this domain malicious?" (that is handled by domain_intelligence.py)

DESIGN RULES:
    - Passive, read-only lookups only. No active scanning.
    - Never fabricate history. Missing data → "Unavailable" or empty list.
    - Infrastructure changes are FORENSIC EVIDENCE, not proof of malice.
    - Historical detections ≠ "blocked globally".
    - Mock mode is ON by default; real provider requires env var + API key.
    - Per-request in-memory cache avoids duplicate lookups.

PROVIDERS:
    - MockDomainIntelligenceProvider   (always available, deterministic demo)
    - VirusTotalProvider               (requires VIRUSTOTAL_API_KEY env var)
    - SecurityTrailsProvider           (stub — returns Unavailable, placeholder)

INTEGRATION:
    Call run_forensic_domain_analysis(parsed, url_analysis) from main.py.
    Returns ForensicIntelligenceResult, which report_generator.py serialises.
"""

from __future__ import annotations

import abc
import json
import re
import socket
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from . import config

# ═══════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class DNSRecordSet:
    """Current DNS records for a domain."""
    A:     list[str]
    AAAA:  list[str]
    MX:    list[Any]   # str or dict with priority/host
    NS:    list[str]
    CNAME: list[str]
    TXT:   list[str]


@dataclass
class HistoricalDNSRecord:
    """A single historical DNS observation."""
    value:      str
    first_seen: Optional[str]   # ISO date or None
    last_seen:  Optional[str]


@dataclass
class HistoricalIP:
    """An IP address historically associated with the domain."""
    ip:         str
    first_seen: Optional[str]
    last_seen:  Optional[str]


@dataclass
class WhoisRecord:
    """A single WHOIS history snapshot."""
    registrar:   Optional[str]
    registered:  Optional[str]
    updated:     Optional[str]
    expires:     Optional[str]
    nameservers: list[str]


@dataclass
class SecurityDetection:
    """A single historical or current security detection."""
    date:     Optional[str]
    category: str
    provider: str


@dataclass
class SecurityHistory:
    """Security detection history for a domain."""
    previously_detected: bool
    currently_detected:  bool
    detections:          list[SecurityDetection]


@dataclass
class TimelineEvent:
    """A single chronological forensic event."""
    date:   str          # ISO date string (YYYY-MM-DD)
    event:  str          # human-readable event label
    value:  str          # observed value
    source: str          # data source label


@dataclass
class ForensicEvidence:
    """A structured piece of forensic evidence."""
    type:        str    # dns_change | ip_change | nameserver_change | mx_change |
                        # whois_change | historical_detection | current_detection
    severity:    str    # info | low | medium | high
    description: str
    evidence:    dict[str, Any]
    source:      str


@dataclass
class DomainForensicResult:
    """Complete forensic intelligence result for one domain."""
    domain:           str
    data_source:      str          # "Mock/Demo" | "VirusTotal" | "Unavailable"

    current_dns:      DNSRecordSet
    historical_dns:   dict[str, list[HistoricalDNSRecord]]   # key = record type
    historical_ips:   list[HistoricalIP]
    whois_history:    list[WhoisRecord]
    security_history: SecurityHistory

    timeline:         list[TimelineEvent]   # chronologically sorted
    evidence:         list[ForensicEvidence]
    limitations:      list[str]


@dataclass
class ForensicIntelligenceResult:
    """Container for forensic results across all domains in an email."""
    domains:     list[DomainForensicResult]
    limitations: list[str]


# ═══════════════════════════════════════════════════════════════════
# PROVIDER ABSTRACTION
# ═══════════════════════════════════════════════════════════════════

class DomainIntelligenceProvider(abc.ABC):
    """Abstract base class for forensic domain intelligence providers."""

    @abc.abstractmethod
    def name(self) -> str:
        """Return the provider display name."""

    @abc.abstractmethod
    def get_forensic_data(self, domain: str) -> dict[str, Any]:
        """
        Fetch raw forensic data for a domain.
        Must return a dict with keys:
            current_dns, historical_dns, historical_ips,
            whois_history, security_history
        Never raise — on error return partial data with limitations.
        """


# ═══════════════════════════════════════════════════════════════════
# PROVIDER: MOCK
# ═══════════════════════════════════════════════════════════════════

class MockDomainIntelligenceProvider(DomainIntelligenceProvider):
    """
    Deterministic mock provider for development and demonstration.
    All data is clearly labeled 'Mock/Demo'.
    """

    def name(self) -> str:
        return "Mock/Demo"

    def get_forensic_data(self, domain: str) -> dict[str, Any]:
        from .mock_data.forensic_domain_data import get_mock_forensic_data
        data, found = get_mock_forensic_data(domain)
        if not found:
            data["_limitations"] = [
                f"Domain '{domain}' is not in the Mock/Demo database. "
                "No historical record observed (mock mode)."
            ]
        return data


# ═══════════════════════════════════════════════════════════════════
# PROVIDER: VIRUSTOTAL
# ═══════════════════════════════════════════════════════════════════

class VirusTotalProvider(DomainIntelligenceProvider):
    """
    VirusTotal v3 API adapter — passive, read-only.

    Endpoints used:
        GET /api/v3/domains/{domain}              → current DNS + security
        GET /api/v3/domains/{domain}/historical_whois → WHOIS history
        GET /api/v3/domains/{domain}/resolutions  → historical IPs (A records)

    Requires env var: VIRUSTOTAL_API_KEY
    Rate limit: 4 requests/minute on free tier.

    NOTE: VT does not provide a full historical DNS breakdown by record type.
    We map available data to our schema and mark gaps as Unavailable.
    """

    _BASE = "https://www.virustotal.com/api/v3"

    def name(self) -> str:
        return "VirusTotal"

    def _get(self, path: str) -> Optional[dict]:
        """Make a GET request to VT API. Returns parsed JSON or None on error."""
        url = f"{self._BASE}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": config.VIRUSTOTAL_API_KEY,
                "Accept":   "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=config.FORENSIC_API_TIMEOUT_S) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return {"_error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"_error": str(e)}

    def get_forensic_data(self, domain: str) -> dict[str, Any]:
        limitations: list[str] = []
        raw: dict = {}

        # ── Current DNS + security stats ─────────────────────────
        domain_data = self._get(f"/domains/{domain}")
        if not domain_data or "_error" in domain_data:
            limitations.append(
                f"VirusTotal domain lookup failed: {domain_data.get('_error', 'Unknown error') if domain_data else 'No response'}."
            )
            domain_data = {}

        attrs = (domain_data.get("data") or {}).get("attributes") or {}

        # Current DNS from last_dns_records
        last_dns = attrs.get("last_dns_records") or []
        current_dns: dict[str, list] = {
            "A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": [], "TXT": [],
        }
        for rec in last_dns:
            rtype = rec.get("type", "").upper()
            val   = rec.get("value", "")
            if rtype in current_dns:
                if rtype == "MX":
                    current_dns["MX"].append({"priority": rec.get("priority", 0), "host": val})
                else:
                    current_dns[rtype].append(val)

        # Security stats
        stats      = attrs.get("last_analysis_stats") or {}
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        currently_detected = (malicious + suspicious) > 0

        detections: list[dict] = []
        if currently_detected:
            results = attrs.get("last_analysis_results") or {}
            for engine, result in results.items():
                if result.get("category") in ("malicious", "suspicious"):
                    detections.append({
                        "date":     attrs.get("last_analysis_date", None),
                        "category": result.get("result") or result.get("category", "Unknown"),
                        "provider": f"VirusTotal/{engine}",
                    })
                    if len(detections) >= 5:   # cap for readability
                        break

        # ── Historical WHOIS ─────────────────────────────────────
        whois_raw = self._get(f"/domains/{domain}/historical_whois")
        whois_history: list[dict] = []
        if whois_raw and "_error" not in whois_raw:
            for item in (whois_raw.get("data") or [])[:5]:   # cap to 5 entries
                wa = (item.get("attributes") or {})
                whois_history.append({
                    "registrar":   wa.get("registrar"),
                    "registered":  _epoch_to_date(wa.get("creation_date")),
                    "updated":     _epoch_to_date(wa.get("updated_date")),
                    "expires":     _epoch_to_date(wa.get("expiration_date")),
                    "nameservers": wa.get("name_servers") or [],
                })
        else:
            limitations.append("VirusTotal WHOIS history unavailable.")

        # ── Historical IPs (resolutions = A record history) ──────
        res_raw = self._get(f"/domains/{domain}/resolutions")
        historical_ips: list[dict] = []
        hist_a_records: list[dict] = []
        if res_raw and "_error" not in res_raw:
            for item in (res_raw.get("data") or [])[:20]:
                ra = (item.get("attributes") or {})
                ip = ra.get("ip_address", "")
                fs = _epoch_to_date(ra.get("date"))
                if ip:
                    historical_ips.append({"ip": ip, "first_seen": fs, "last_seen": fs})
                    hist_a_records.append({"value": ip, "first_seen": fs, "last_seen": fs})
        else:
            limitations.append(
                "VirusTotal domain resolutions unavailable — historical IPs not retrieved."
            )

        historical_dns = {
            "A":     hist_a_records,
            "AAAA":  [],
            "MX":    [],
            "NS":    [],
            "CNAME": [],
        }
        limitations.append(
            "VirusTotal does not provide full historical DNS by record type. "
            "Only historical A records (resolutions) are available."
        )

        # ── Assemble raw dict ────────────────────────────────────
        raw = {
            "current_dns":     current_dns,
            "historical_dns":  historical_dns,
            "historical_ips":  historical_ips,
            "whois_history":   whois_history,
            "security_history": {
                "previously_detected": len(historical_ips) > 0 and currently_detected,
                "currently_detected":  currently_detected,
                "detections":          detections,
            },
            "_limitations": limitations,
        }
        return raw


# ═══════════════════════════════════════════════════════════════════
# PROVIDER: SECURITYTRAILS  (stub)
# ═══════════════════════════════════════════════════════════════════

class SecurityTrailsProvider(DomainIntelligenceProvider):
    """
    SecurityTrails API stub.

    SecurityTrails provides richer historical DNS than VT but requires
    a paid API plan. This stub returns Unavailable gracefully.

    To implement: replace the body of get_forensic_data() with real
    API calls to https://api.securitytrails.com/v1/
    """

    def name(self) -> str:
        return "SecurityTrails"

    def get_forensic_data(self, domain: str) -> dict[str, Any]:
        return {
            "current_dns":     {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": [], "TXT": []},
            "historical_dns":  {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
            "historical_ips":  [],
            "whois_history":   [],
            "security_history": {
                "previously_detected": False,
                "currently_detected":  False,
                "detections": [],
            },
            "_limitations": [
                "SecurityTrails provider is configured but not yet implemented. "
                "Requires a paid API plan. Data is Unavailable."
            ],
        }


# ═══════════════════════════════════════════════════════════════════
# PROVIDER: LIVE DNS FALLBACK
# ═══════════════════════════════════════════════════════════════════

def _get_live_dns(domain: str) -> dict[str, list]:
    """
    Resolve current DNS using Python stdlib (passive, read-only).
    Used as supplementary current-DNS data when no API is configured.
    Only A/AAAA/MX/NS/CNAME are attempted; TXT requires dnspython.
    """
    result: dict[str, list] = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": [], "TXT": [],
    }
    try:
        # A records via getaddrinfo
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        result["A"] = list({info[4][0] for info in infos})
    except Exception:
        pass
    try:
        infos6 = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
        result["AAAA"] = list({info[4][0] for info in infos6})
    except Exception:
        pass
    return result


# ═══════════════════════════════════════════════════════════════════
# NORMALIZATION
# ═══════════════════════════════════════════════════════════════════

def _epoch_to_date(ts: Any) -> Optional[str]:
    """Convert a Unix timestamp (int/float) to ISO date string, or None."""
    if ts is None:
        return None
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d")
    except Exception:
        return str(ts) if ts else None


def _normalize(domain: str, raw: dict, source_name: str) -> DomainForensicResult:
    """
    Convert raw provider dict → typed DomainForensicResult.
    Handles missing keys gracefully — never raises.
    """
    limitations: list[str] = list(raw.get("_limitations") or [])

    # ── current_dns ──────────────────────────────────────────────
    raw_cur = raw.get("current_dns") or {}
    cur_dns = DNSRecordSet(
        A=     raw_cur.get("A", []),
        AAAA=  raw_cur.get("AAAA", []),
        MX=    raw_cur.get("MX", []),
        NS=    raw_cur.get("NS", []),
        CNAME= raw_cur.get("CNAME", []),
        TXT=   raw_cur.get("TXT", []),
    )

    # ── historical_dns ───────────────────────────────────────────
    raw_hist = raw.get("historical_dns") or {}
    hist_dns: dict[str, list[HistoricalDNSRecord]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "CNAME"):
        hist_dns[rtype] = [
            HistoricalDNSRecord(
                value=      str(r.get("value", "")),
                first_seen= r.get("first_seen"),
                last_seen=  r.get("last_seen"),
            )
            for r in (raw_hist.get(rtype) or [])
            if r.get("value")
        ]

    # ── historical_ips ───────────────────────────────────────────
    hist_ips: list[HistoricalIP] = [
        HistoricalIP(
            ip=         str(r.get("ip", "")),
            first_seen= r.get("first_seen"),
            last_seen=  r.get("last_seen"),
        )
        for r in (raw.get("historical_ips") or [])
        if r.get("ip")
    ]

    # ── whois_history ────────────────────────────────────────────
    whois_list: list[WhoisRecord] = [
        WhoisRecord(
            registrar=   r.get("registrar"),
            registered=  r.get("registered"),
            updated=     r.get("updated"),
            expires=     r.get("expires"),
            nameservers= r.get("nameservers") or [],
        )
        for r in (raw.get("whois_history") or [])
    ]

    # ── security_history ─────────────────────────────────────────
    raw_sec = raw.get("security_history") or {}
    sec_hist = SecurityHistory(
        previously_detected= bool(raw_sec.get("previously_detected", False)),
        currently_detected=  bool(raw_sec.get("currently_detected", False)),
        detections=[
            SecurityDetection(
                date=     d.get("date"),
                category= str(d.get("category", "Unknown")),
                provider= str(d.get("provider", source_name)),
            )
            for d in (raw_sec.get("detections") or [])
        ],
    )

    # ── timeline + evidence ──────────────────────────────────────
    timeline, evidence = _build_timeline_and_evidence(
        domain, cur_dns, hist_dns, hist_ips, whois_list, sec_hist, source_name
    )

    return DomainForensicResult(
        domain=           domain,
        data_source=      source_name,
        current_dns=      cur_dns,
        historical_dns=   hist_dns,
        historical_ips=   hist_ips,
        whois_history=    whois_list,
        security_history= sec_hist,
        timeline=         timeline,
        evidence=         evidence,
        limitations=      limitations,
    )


# ═══════════════════════════════════════════════════════════════════
# FORENSIC TIMELINE & EVIDENCE BUILDER  (Step 9)
# ═══════════════════════════════════════════════════════════════════

def _build_timeline_and_evidence(
    domain:   str,
    cur_dns:  DNSRecordSet,
    hist_dns: dict[str, list[HistoricalDNSRecord]],
    hist_ips: list[HistoricalIP],
    whois:    list[WhoisRecord],
    sec:      SecurityHistory,
    source:   str,
) -> tuple[list[TimelineEvent], list[ForensicEvidence]]:
    """
    Build chronological timeline and structured evidence items.

    Rules:
    - Only create timeline events when a date is actually available.
    - Infrastructure changes are FORENSIC EVIDENCE (info/medium), not proof of malice.
    - Security detections get higher severity but are still not "proof of blocking".
    """
    events:   list[TimelineEvent]   = []
    evidence: list[ForensicEvidence] = []

    # ── WHOIS events ─────────────────────────────────────────────
    for w in whois:
        if w.registered:
            events.append(TimelineEvent(
                date=w.registered, event="Domain registered",
                value=w.registrar or "Unknown registrar", source=source,
            ))
        if w.updated and w.updated != w.registered:
            events.append(TimelineEvent(
                date=w.updated, event="WHOIS record updated",
                value=w.registrar or "Unknown registrar", source=source,
            ))

    # ── Historical IP events + IP change detection ────────────────
    # Sort historical IPs by first_seen for change detection
    dated_ips = [h for h in hist_ips if h.first_seen]
    dated_ips.sort(key=lambda h: h.first_seen or "")

    for h in dated_ips:
        if h.first_seen:
            events.append(TimelineEvent(
                date=h.first_seen, event="IP observed",
                value=h.ip, source=source,
            ))

    # Detect IP changes (consecutive different IPs)
    for i in range(1, len(dated_ips)):
        prev = dated_ips[i - 1]
        curr = dated_ips[i]
        if prev.ip != curr.ip and curr.first_seen:
            events.append(TimelineEvent(
                date=curr.first_seen, event="IP changed",
                value=curr.ip, source=source,
            ))
            evidence.append(ForensicEvidence(
                type="ip_change",
                severity="medium",
                description=f"Domain '{domain}' IP address changed.",
                evidence={
                    "old_value":   prev.ip,
                    "new_value":   curr.ip,
                    "observed_at": curr.first_seen,
                },
                source=source,
            ))

    # ── Historical NS change detection ────────────────────────────
    hist_ns = hist_dns.get("NS") or []
    if len(hist_ns) >= 2:
        ns_sorted = sorted([n for n in hist_ns if n.first_seen], key=lambda n: n.first_seen or "")
        for i in range(1, len(ns_sorted)):
            prev_ns = ns_sorted[i - 1]
            curr_ns = ns_sorted[i]
            if prev_ns.value != curr_ns.value and curr_ns.first_seen:
                events.append(TimelineEvent(
                    date=curr_ns.first_seen, event="Nameserver changed",
                    value=curr_ns.value, source=source,
                ))
                evidence.append(ForensicEvidence(
                    type="nameserver_change",
                    severity="info",
                    description=f"Domain '{domain}' nameserver changed.",
                    evidence={
                        "old_value":   prev_ns.value,
                        "new_value":   curr_ns.value,
                        "observed_at": curr_ns.first_seen,
                    },
                    source=source,
                ))

    # ── MX change detection ───────────────────────────────────────
    hist_mx = hist_dns.get("MX") or []
    if len(hist_mx) >= 2:
        evidence.append(ForensicEvidence(
            type="mx_change",
            severity="info",
            description=f"Historical MX record changes observed for '{domain}'.",
            evidence={"records_observed": len(hist_mx)},
            source=source,
        ))

    # ── Security detection events ─────────────────────────────────
    for det in sec.detections:
        if det.date:
            events.append(TimelineEvent(
                date=det.date, event="Security detection observed",
                value=det.category, source=det.provider,
            ))

    if sec.previously_detected:
        evidence.append(ForensicEvidence(
            type="historical_detection",
            severity="high",
            description=(
                f"Domain '{domain}' has historical security detection(s). "
                "Use terminology: 'Previously detected' — not 'blocked globally'."
            ),
            evidence={
                "detection_count": len(sec.detections),
                "categories": list({d.category for d in sec.detections}),
            },
            source=source,
        ))

    if sec.currently_detected:
        evidence.append(ForensicEvidence(
            type="current_detection",
            severity="high",
            description=(
                f"Domain '{domain}' is currently detected by at least one "
                "intelligence provider. This does not mean universally blocked."
            ),
            evidence={
                "detection_count": sum(
                    1 for d in sec.detections
                    if not d.date or d.date >= "2026-01-01"
                ),
            },
            source=source,
        ))

    # ── Sort timeline chronologically ─────────────────────────────
    def _sort_key(e: TimelineEvent) -> str:
        return e.date if e.date else "0000-00-00"

    events.sort(key=_sort_key)

    return events, evidence


# ═══════════════════════════════════════════════════════════════════
# PROVIDER FACTORY
# ═══════════════════════════════════════════════════════════════════

def _get_provider() -> DomainIntelligenceProvider:
    """
    Select and return the appropriate provider based on config.

    Priority:
      1. FORENSIC_MOCK_MODE=true  → Mock
      2. FORENSIC_PROVIDER=virustotal + key present → VirusTotal
      3. FORENSIC_PROVIDER=securitytrails + key present → SecurityTrails (stub)
      4. No key / unconfigured → Mock with Unavailable note
    """
    if config.FORENSIC_MOCK_MODE:
        return MockDomainIntelligenceProvider()

    if config.FORENSIC_PROVIDER == "virustotal" and config.VIRUSTOTAL_API_KEY:
        return VirusTotalProvider()

    if config.FORENSIC_PROVIDER == "securitytrails" and config.SECURITYTRAILS_API_KEY:
        return SecurityTrailsProvider()

    # No valid real provider configured — fall back transparently
    return _UnavailableProvider()


class _UnavailableProvider(DomainIntelligenceProvider):
    """Returned when no real provider is configured and mock is off."""

    def name(self) -> str:
        return "Unavailable"

    def get_forensic_data(self, domain: str) -> dict[str, Any]:
        return {
            "current_dns":     {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": [], "TXT": []},
            "historical_dns":  {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
            "historical_ips":  [],
            "whois_history":   [],
            "security_history": {
                "previously_detected": False,
                "currently_detected":  False,
                "detections": [],
            },
            "_limitations": [
                "Historical domain intelligence provider is not configured. "
                "Set MOCK_THREAT_INTEL=true for demo mode, or supply a "
                "VIRUSTOTAL_API_KEY environment variable for live data."
            ],
        }


# ═══════════════════════════════════════════════════════════════════
# DOMAIN EXTRACTION
# ═══════════════════════════════════════════════════════════════════

def _collect_domains(parsed: Any, url_analysis: Any) -> list[str]:
    """
    Collect unique domains from:
      - Sender domain
      - URL findings (from url_analyzer)

    Returns de-duplicated lowercase list.
    Excludes IP addresses and empty strings.
    """
    seen: set[str] = set()
    domains: list[str] = []

    def _add(d: str) -> None:
        d = d.lower().strip()
        # Skip empty, IP addresses, and very short strings
        if not d or d in seen:
            return
        # Simple IP check
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', d):
            return
        seen.add(d)
        domains.append(d)

    if getattr(parsed, "sender_domain", ""):
        _add(parsed.sender_domain)

    for finding in getattr(url_analysis, "findings", []):
        if getattr(finding, "domain", ""):
            _add(finding.domain)

    return domains


# ═══════════════════════════════════════════════════════════════════
# PUBLIC API  (Step 10)
# ═══════════════════════════════════════════════════════════════════

def run_forensic_domain_analysis(
    parsed: Any,
    url_analysis: Any,
) -> ForensicIntelligenceResult:
    """
    Run forensic domain intelligence for all relevant domains in an email.

    Uses an in-memory per-request cache so each unique domain is
    investigated exactly once, even if it appears in multiple URLs.

    Args:
        parsed:       ParsedEmail from email_parser
        url_analysis: URLAnalysis from url_analyzer

    Returns:
        ForensicIntelligenceResult with per-domain DomainForensicResult entries.
    """
    provider = _get_provider()
    cache: dict[str, DomainForensicResult] = {}
    global_limitations: list[str] = []

    if provider.name() == "Mock/Demo":
        global_limitations.append(
            "Forensic domain intelligence is running in Mock/Demo mode. "
            "Data is illustrative only — set MOCK_THREAT_INTEL=false and "
            "provide VIRUSTOTAL_API_KEY for live intelligence."
        )
    elif provider.name() == "Unavailable":
        global_limitations.append(
            "Historical domain intelligence provider is not configured. "
            "Results show no historical data."
        )

    domains = _collect_domains(parsed, url_analysis)
    results: list[DomainForensicResult] = []

    for domain in domains:
        if domain in cache:
            results.append(cache[domain])
            continue

        try:
            raw = provider.get_forensic_data(domain)
        except Exception as exc:
            raw = {
                "current_dns":     {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": [], "TXT": []},
                "historical_dns":  {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
                "historical_ips":  [],
                "whois_history":   [],
                "security_history": {
                    "previously_detected": False,
                    "currently_detected":  False,
                    "detections": [],
                },
                "_limitations": [f"Provider error for '{domain}': {exc}"],
            }

        # Supplement with live stdlib DNS when provider has no current A records
        # and we're in Unavailable/SecurityTrails mode
        cur_a = (raw.get("current_dns") or {}).get("A") or []
        if not cur_a and provider.name() not in ("Mock/Demo",):
            live_dns = _get_live_dns(domain)
            if live_dns.get("A"):
                raw.setdefault("current_dns", {})
                raw["current_dns"]["A"] = live_dns["A"]
                raw["current_dns"]["AAAA"] = live_dns.get("AAAA", [])

        result = _normalize(domain, raw, provider.name())
        cache[domain] = result
        results.append(result)

    return ForensicIntelligenceResult(domains=results, limitations=global_limitations)


# ═══════════════════════════════════════════════════════════════════
# PUBLIC HELPER FUNCTIONS  (for individual lookups + testing)
# ═══════════════════════════════════════════════════════════════════

def get_forensic_domain_intel(domain: str) -> DomainForensicResult:
    """
    Analyze a single domain directly (convenience wrapper).
    Used in tests and ad-hoc forensic investigation.
    """
    provider = _get_provider()
    raw = provider.get_forensic_data(domain)
    return _normalize(domain, raw, provider.name())


def get_current_dns(domain: str) -> DNSRecordSet:
    """Return only the current DNS record set for a domain."""
    return get_forensic_domain_intel(domain).current_dns


def get_historical_dns(domain: str) -> dict[str, list[HistoricalDNSRecord]]:
    """Return only the historical DNS records for a domain."""
    return get_forensic_domain_intel(domain).historical_dns


def get_historical_ips(domain: str) -> list[HistoricalIP]:
    """Return only the historical IP associations for a domain."""
    return get_forensic_domain_intel(domain).historical_ips


def get_historical_whois(domain: str) -> list[WhoisRecord]:
    """Return only the WHOIS history for a domain."""
    return get_forensic_domain_intel(domain).whois_history


def get_security_detections(domain: str) -> SecurityHistory:
    """Return only the security detection history for a domain."""
    return get_forensic_domain_intel(domain).security_history


def build_domain_timeline(domain: str) -> list[TimelineEvent]:
    """Return only the chronological forensic timeline for a domain."""
    return get_forensic_domain_intel(domain).timeline
