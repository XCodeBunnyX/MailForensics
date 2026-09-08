"""
GmailGuard — OSINT Intelligence Layer

Investigates indicators extracted from emails (Domains, IPs, URLs, Sender Domains)
using legitimate passive and public threat intelligence sources.

ARCHITECTURAL PRINCIPLES:
    - OSINT IS NOT A MACHINE-LEARNING MODEL. It is an intelligence-gathering
      and correlation layer feeding the forensic investigation.
    - Passive, non-intrusive operations only. No port scans, no brute-force,
      no exploitation, no live payload execution.
    - Pluggable provider abstraction (Mock, VirusTotal, SecurityTrails-stub, Unavailable).
    - Strict deduplication: indicators are investigated at most once.
    - Honest reporting: Missing data is tagged "Unavailable", never fabricated.
    - Objective terminology: Uses "Observable Infrastructure Location",
      "Observed IP", and "Security observation detected".
"""

from __future__ import annotations

import abc
import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

import config
from ioc_extractor import IOCBundle
from mock_data.osint_mock_data import get_mock_ip_osint, get_mock_url_osint
from forensic_domain_intelligence import (
    DomainForensicResult,
    ForensicIntelligenceResult,
    get_forensic_domain_intel,
)


# ═══════════════════════════════════════════════════════════════════
# NORMALIZED OSINT SCHEMAS
# ═══════════════════════════════════════════════════════════════════

@dataclass
class NormalizedOSINTRecord:
    """
    Normalized response structure for any investigated indicator
    (Domain, IP, URL, or Sender Domain).
    """
    indicator: str
    indicator_type: str                     # "domain" | "ip" | "url" | "sender_domain"
    data_source: str                        # "Mock/Demo" | "VirusTotal" | "Unavailable"
    current_information: dict[str, Any]
    historical_information: dict[str, Any]
    security_observations: list[dict[str, Any]]
    related_infrastructure: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "data_source": self.data_source,
            "current_information": self.current_information,
            "historical_information": self.historical_information,
            "security_observations": self.security_observations,
            "related_infrastructure": self.related_infrastructure,
            "timeline": self.timeline,
            "evidence": self.evidence,
            "limitations": self.limitations,
        }


@dataclass
class OSINTAnalysisResult:
    """Consolidated OSINT intelligence for all indicators extracted from an email."""
    domains: list[NormalizedOSINTRecord]
    ips: list[NormalizedOSINTRecord]
    urls: list[NormalizedOSINTRecord]
    data_source: str
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domains": [d.to_dict() for d in self.domains],
            "ips": [ip.to_dict() for ip in self.ips],
            "urls": [u.to_dict() for u in self.urls],
            "data_source": self.data_source,
            "limitations": self.limitations,
        }


# ═══════════════════════════════════════════════════════════════════
# PROVIDER ABSTRACTION
# ═══════════════════════════════════════════════════════════════════

class OSINTProvider(abc.ABC):
    """Abstract interface for passive OSINT intelligence providers."""

    @abc.abstractmethod
    def name(self) -> str:
        """Return provider display name."""
        ...

    @abc.abstractmethod
    def investigate_domain(self, domain: str, is_sender: bool = False) -> NormalizedOSINTRecord:
        """Investigate a domain indicator."""
        ...

    @abc.abstractmethod
    def investigate_ip(self, ip: str) -> NormalizedOSINTRecord:
        """Investigate an IP address indicator."""
        ...

    @abc.abstractmethod
    def investigate_url(self, url: str) -> NormalizedOSINTRecord:
        """Investigate a URL indicator."""
        ...


# ───────────────────────────────────────────────────────────────────
# 1. Mock OSINT Provider (Deterministic Demo)
# ───────────────────────────────────────────────────────────────────

class MockOSINTProvider(OSINTProvider):
    """
    Deterministic mock provider for offline demonstration and testing.
    Every record is explicitly stamped with data_source: 'Mock/Demo'.
    """

    def name(self) -> str:
        return "Mock/Demo"

    def investigate_domain(self, domain: str, is_sender: bool = False) -> NormalizedOSINTRecord:
        # Reuses existing forensic domain intelligence mock pipeline
        forensic_res: DomainForensicResult = get_forensic_domain_intel(domain)

        # Extract latest registrar / registration info
        registrar = "Unavailable"
        registered = "Unavailable"
        expires = "Unavailable"
        if forensic_res.whois_history:
            latest_w = forensic_res.whois_history[0]
            registrar = latest_w.registrar or "Unavailable"
            registered = latest_w.registered or "Unavailable"
            expires = latest_w.expires or "Unavailable"

        current_info = {
            "dns": {
                "A": forensic_res.current_dns.A,
                "AAAA": forensic_res.current_dns.AAAA,
                "MX": forensic_res.current_dns.MX,
                "NS": forensic_res.current_dns.NS,
                "CNAME": forensic_res.current_dns.CNAME,
                "TXT": forensic_res.current_dns.TXT,
            },
            "registration": {
                "registrar": registrar,
                "registered": registered,
                "expires": expires,
            },
            "reputation": {
                "previously_detected": forensic_res.security_history.previously_detected,
                "currently_detected": forensic_res.security_history.currently_detected,
            },
        }

        historical_info = {
            "dns": [
                {"type": rtype, "value": r.value, "first_seen": r.first_seen, "last_seen": r.last_seen}
                for rtype, records in forensic_res.historical_dns.items()
                for r in records
            ],
            "ips": [
                {"ip": h.ip, "first_seen": h.first_seen, "last_seen": h.last_seen}
                for h in forensic_res.historical_ips
            ],
            "nameservers": [
                ns for w in forensic_res.whois_history for ns in w.nameservers
            ],
            "whois": [
                {
                    "registrar": w.registrar,
                    "registered": w.registered,
                    "updated": w.updated,
                    "expires": w.expires,
                    "nameservers": w.nameservers,
                }
                for w in forensic_res.whois_history
            ],
        }

        security_obs = [
            {
                "date": d.date,
                "category": d.category,
                "provider": d.provider,
                "finding": f"Security observation detected: {d.category}",
            }
            for d in forensic_res.security_history.detections
        ]

        # Related infrastructure based on historical and current IPs
        related_infra: list[dict[str, Any]] = []
        for ip in forensic_res.current_dns.A:
            related_infra.append({
                "relationship": "Observable Mail / Host Infrastructure IP",
                "target": ip,
                "source": "Mock/Demo",
            })

        timeline_events = [
            {
                "date": t.date,
                "event": t.event,
                "value": t.value,
                "source": t.source,
            }
            for t in forensic_res.timeline
        ]

        evidence_items = [
            {
                "source": "OSINT/Domain",
                "finding": e.description,
                "severity": e.severity,
            }
            for e in forensic_res.evidence
        ]

        return NormalizedOSINTRecord(
            indicator=domain,
            indicator_type="sender_domain" if is_sender else "domain",
            data_source="Mock/Demo",
            current_information=current_info,
            historical_information=historical_info,
            security_observations=security_obs,
            related_infrastructure=related_infra,
            timeline=timeline_events,
            evidence=evidence_items,
            limitations=list(forensic_res.limitations),
        )

    def investigate_ip(self, ip: str) -> NormalizedOSINTRecord:
        raw, _ = get_mock_ip_osint(ip)
        return NormalizedOSINTRecord(
            indicator=ip,
            indicator_type="ip",
            data_source="Mock/Demo",
            current_information=raw.get("current_information", {}),
            historical_information=raw.get("historical_information", {}),
            security_observations=raw.get("security_observations", []),
            related_infrastructure=raw.get("related_infrastructure", []),
            timeline=raw.get("timeline", []),
            evidence=raw.get("evidence", []),
            limitations=raw.get("limitations", []),
        )

    def investigate_url(self, url: str) -> NormalizedOSINTRecord:
        raw, _ = get_mock_url_osint(url)
        return NormalizedOSINTRecord(
            indicator=url,
            indicator_type="url",
            data_source="Mock/Demo",
            current_information=raw.get("current_information", {}),
            historical_information=raw.get("historical_information", {}),
            security_observations=raw.get("security_observations", []),
            related_infrastructure=raw.get("related_infrastructure", []),
            timeline=raw.get("timeline", []),
            evidence=raw.get("evidence", []),
            limitations=raw.get("limitations", []),
        )


# ───────────────────────────────────────────────────────────────────
# 2. VirusTotal OSINT Provider (Live Passive Intelligence)
# ───────────────────────────────────────────────────────────────────

class VirusTotalOSINTProvider(OSINTProvider):
    """
    Passive VirusTotal v3 intelligence provider for IP, URL, and Domain indicators.
    Uses legitimate public REST endpoints with API key.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.timeout = config.OSINT_API_TIMEOUT_S

    def name(self) -> str:
        return "VirusTotal"

    def _get(self, endpoint: str) -> dict[str, Any]:
        """Execute a passive, authenticated GET request to VirusTotal v3."""
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "User-Agent": "GmailGuard-Forensic-Engine/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def investigate_domain(self, domain: str, is_sender: bool = False) -> NormalizedOSINTRecord:
        try:
            data = self._get(f"domains/{domain}")
            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            # Extract DNS records
            last_dns = attr.get("last_dns_records", [])
            dns_a = [r.get("value") for r in last_dns if r.get("type") == "A" and r.get("value")]
            dns_ns = [r.get("value") for r in last_dns if r.get("type") == "NS" and r.get("value")]
            dns_mx = [r.get("value") for r in last_dns if r.get("type") == "MX" and r.get("value")]

            security_obs = []
            if malicious > 0 or suspicious > 0:
                security_obs.append({
                    "date": "Recent",
                    "category": "Malicious / Suspicious Detections",
                    "provider": "VirusTotal",
                    "finding": f"Security observation detected: {malicious} engine(s) flagged domain.",
                })

            current_info = {
                "dns": {"A": dns_a, "AAAA": [], "MX": dns_mx, "NS": dns_ns, "CNAME": [], "TXT": []},
                "registration": {
                    "registrar": attr.get("registrar", "Unavailable"),
                    "registered": attr.get("creation_date", "Unavailable"),
                    "expires": "Unavailable",
                },
                "reputation": {
                    "previously_detected": malicious > 0 or suspicious > 0,
                    "currently_detected": malicious > 0,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                },
            }

            timeline: list[dict[str, Any]] = []
            creation_date = attr.get("creation_date")
            if creation_date:
                timeline.append({
                    "date": str(creation_date)[:10],
                    "event": "Domain Registered",
                    "value": domain,
                    "source": "VirusTotal",
                })

            evidence = []
            if malicious >= 3:
                evidence.append({
                    "source": "OSINT/VirusTotal",
                    "finding": f"Domain has {malicious} security vendor detections.",
                    "severity": "high",
                })
            elif malicious > 0:
                evidence.append({
                    "source": "OSINT/VirusTotal",
                    "finding": f"Domain observed with {malicious} security vendor detection(s).",
                    "severity": "medium",
                })

            return NormalizedOSINTRecord(
                indicator=domain,
                indicator_type="sender_domain" if is_sender else "domain",
                data_source="VirusTotal",
                current_information=current_info,
                historical_information={"dns": [], "ips": [], "nameservers": [], "whois": []},
                security_observations=security_obs,
                related_infrastructure=[{"relationship": "Observable IP", "target": ip, "source": "VirusTotal"} for ip in dns_a],
                timeline=timeline,
                evidence=evidence,
                limitations=[],
            )

        except urllib.error.HTTPError as e:
            msg = f"VirusTotal API HTTP {e.code}"
            return NormalizedOSINTRecord(
                indicator=domain,
                indicator_type="sender_domain" if is_sender else "domain",
                data_source="VirusTotal",
                current_information={},
                historical_information={},
                security_observations=[],
                related_infrastructure=[],
                timeline=[],
                evidence=[],
                limitations=[msg],
            )
        except Exception as e:
            return NormalizedOSINTRecord(
                indicator=domain,
                indicator_type="sender_domain" if is_sender else "domain",
                data_source="VirusTotal",
                current_information={},
                historical_information={},
                security_observations=[],
                related_infrastructure=[],
                timeline=[],
                evidence=[],
                limitations=[f"VirusTotal lookup error: {str(e)}"],
            )

    def investigate_ip(self, ip: str) -> NormalizedOSINTRecord:
        try:
            data = self._get(f"ip_addresses/{ip}")
            attr = data.get("data", {}).get("attributes", {})
            asn = str(attr.get("asn", "Unavailable"))
            asn_owner = attr.get("as_owner", "Unavailable")
            country = attr.get("country", "Unavailable")
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)

            current_info = {
                "reverse_dns": attr.get("reverse_dns", "Unavailable"),
                "asn": f"AS{asn}" if not asn.startswith("AS") else asn,
                "isp": asn_owner,
                "org": asn_owner,
                "country": country,
                "reputation": "suspicious" if malicious > 0 else "clean",
            }

            security_obs = []
            if malicious > 0:
                security_obs.append({
                    "date": "Recent",
                    "category": "Observable Infrastructure Detection",
                    "provider": "VirusTotal",
                    "finding": f"Security observation detected: {malicious} engine(s) flagged this IP.",
                })

            evidence = []
            if malicious >= 3:
                evidence.append({
                    "source": "OSINT/VirusTotal",
                    "finding": f"Observable mail infrastructure IP flagged by {malicious} security vendors.",
                    "severity": "high",
                })
            elif malicious > 0:
                evidence.append({
                    "source": "OSINT/VirusTotal",
                    "finding": f"Observed IP has {malicious} vendor detection(s).",
                    "severity": "medium",
                })

            return NormalizedOSINTRecord(
                indicator=ip,
                indicator_type="ip",
                data_source="VirusTotal",
                current_information=current_info,
                historical_information={"dns": [], "ips": [], "nameservers": [], "whois": []},
                security_observations=security_obs,
                related_infrastructure=[{
                    "relationship": "Same infrastructure provider",
                    "target": f"AS{asn} ({asn_owner})",
                    "source": "VirusTotal",
                }],
                timeline=[],
                evidence=evidence,
                limitations=[],
            )

        except urllib.error.HTTPError as e:
            return NormalizedOSINTRecord(
                indicator=ip,
                indicator_type="ip",
                data_source="VirusTotal",
                current_information={},
                historical_information={},
                security_observations=[],
                related_infrastructure=[],
                timeline=[],
                evidence=[],
                limitations=[f"VirusTotal IP lookup returned HTTP {e.code}"],
            )
        except Exception as e:
            return NormalizedOSINTRecord(
                indicator=ip,
                indicator_type="ip",
                data_source="VirusTotal",
                current_information={},
                historical_information={},
                security_observations=[],
                related_infrastructure=[],
                timeline=[],
                evidence=[],
                limitations=[f"VirusTotal IP error: {str(e)}"],
            )

    def investigate_url(self, url: str) -> NormalizedOSINTRecord:
        try:
            # VirusTotal v3 URL identifier: Base64 without '=' padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            data = self._get(f"urls/{url_id}")
            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            categories = list(attr.get("categories", {}).values())

            current_info = {
                "reputation": "suspicious" if (malicious > 0 or suspicious > 0) else "clean",
                "detection_count": malicious,
                "total_engines": sum(stats.values()) if stats else 0,
                "categories": categories,
            }

            security_obs = []
            if malicious > 0:
                security_obs.append({
                    "date": "Recent",
                    "category": "URL Detection",
                    "provider": "VirusTotal",
                    "finding": f"Security observation detected: {malicious} engine(s) flagged URL.",
                })

            evidence = []
            if malicious >= 3:
                evidence.append({
                    "source": "OSINT/VirusTotal",
                    "finding": f"URL confirmed malicious by {malicious} security engines.",
                    "severity": "high",
                })
            elif malicious > 0:
                evidence.append({
                    "source": "OSINT/VirusTotal",
                    "finding": f"URL flagged by {malicious} security engine(s).",
                    "severity": "medium",
                })

            return NormalizedOSINTRecord(
                indicator=url,
                indicator_type="url",
                data_source="VirusTotal",
                current_information=current_info,
                historical_information={"dns": [], "ips": [], "nameservers": [], "whois": []},
                security_observations=security_obs,
                related_infrastructure=[],
                timeline=[],
                evidence=evidence,
                limitations=["Passive lookup: HTTP redirects were not actively traversed."],
            )

        except urllib.error.HTTPError as e:
            return NormalizedOSINTRecord(
                indicator=url,
                indicator_type="url",
                data_source="VirusTotal",
                current_information={},
                historical_information={},
                security_observations=[],
                related_infrastructure=[],
                timeline=[],
                evidence=[],
                limitations=[f"VirusTotal URL lookup returned HTTP {e.code}"],
            )
        except Exception as e:
            return NormalizedOSINTRecord(
                indicator=url,
                indicator_type="url",
                data_source="VirusTotal",
                current_information={},
                historical_information={},
                security_observations=[],
                related_infrastructure=[],
                timeline=[],
                evidence=[],
                limitations=[f"VirusTotal URL error: {str(e)}"],
            )


# ───────────────────────────────────────────────────────────────────
# 3. SecurityTrails Provider (Stub)
# ───────────────────────────────────────────────────────────────────

class SecurityTrailsProvider(OSINTProvider):
    """SecurityTrails OSINT provider stub."""

    def name(self) -> str:
        return "SecurityTrails"

    def investigate_domain(self, domain: str, is_sender: bool = False) -> NormalizedOSINTRecord:
        return _make_unavailable_record(domain, "sender_domain" if is_sender else "domain", "SecurityTrails API requires paid enterprise plan.")

    def investigate_ip(self, ip: str) -> NormalizedOSINTRecord:
        return _make_unavailable_record(ip, "ip", "SecurityTrails IP history requires paid enterprise plan.")

    def investigate_url(self, url: str) -> NormalizedOSINTRecord:
        return _make_unavailable_record(url, "url", "SecurityTrails does not provide URL-level analysis.")


# ───────────────────────────────────────────────────────────────────
# 4. Unavailable OSINT Provider (Fallback when no key configured)
# ───────────────────────────────────────────────────────────────────

def _make_unavailable_record(indicator: str, ind_type: str, reason: str = "") -> NormalizedOSINTRecord:
    limitation = reason or "Historical/public intelligence provider is not configured."
    return NormalizedOSINTRecord(
        indicator=indicator,
        indicator_type=ind_type,
        data_source="Unavailable",
        current_information={},
        historical_information={},
        security_observations=[],
        related_infrastructure=[],
        timeline=[],
        evidence=[],
        limitations=[limitation],
    )


class UnavailableOSINTProvider(OSINTProvider):
    """Used when MOCK_OSINT=false and no provider API keys are configured."""

    def name(self) -> str:
        return "Unavailable"

    def investigate_domain(self, domain: str, is_sender: bool = False) -> NormalizedOSINTRecord:
        return _make_unavailable_record(domain, "sender_domain" if is_sender else "domain")

    def investigate_ip(self, ip: str) -> NormalizedOSINTRecord:
        return _make_unavailable_record(ip, "ip")

    def investigate_url(self, url: str) -> NormalizedOSINTRecord:
        return _make_unavailable_record(url, "url")


# ═══════════════════════════════════════════════════════════════════
# FACTORY & ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

def get_osint_provider() -> OSINTProvider:
    """
    Resolve the active OSINT provider based on config and credentials.
    Priority:
        1. If MOCK_OSINT is True (default) -> MockOSINTProvider
        2. If VIRUSTOTAL_API_KEY is present -> VirusTotalOSINTProvider
        3. Fallback -> UnavailableOSINTProvider
    """
    if config.MOCK_OSINT:
        return MockOSINTProvider()

    if config.VIRUSTOTAL_API_KEY:
        return VirusTotalOSINTProvider(config.VIRUSTOTAL_API_KEY)

    return UnavailableOSINTProvider()


def run_osint_analysis(
    ioc_bundle: IOCBundle,
    provider: Optional[OSINTProvider] = None,
) -> OSINTAnalysisResult:
    """
    Run OSINT investigations on all deduplicated indicators in the bundle.
    Guarantees:
    - Each domain, IP, and URL is investigated only once.
    - Safe and passive operation.
    - Normalized output schema matching GmailGuard standards.
    """
    active_provider = provider or get_osint_provider()
    provider_name = active_provider.name()

    domain_records: list[NormalizedOSINTRecord] = []
    ip_records: list[NormalizedOSINTRecord] = []
    url_records: list[NormalizedOSINTRecord] = []
    limitations: list[str] = []

    # 1. Investigate Domains
    investigated_domains: set[str] = set()
    for dom in ioc_bundle.domains:
        if not dom or dom in investigated_domains:
            continue
        investigated_domains.add(dom)
        is_sender = (dom == ioc_bundle.sender_domain)
        rec = active_provider.investigate_domain(dom, is_sender=is_sender)
        domain_records.append(rec)
        limitations.extend(rec.limitations)

    # 2. Investigate IPs
    investigated_ips: set[str] = set()
    for ip in ioc_bundle.ips:
        if not ip or ip in investigated_ips:
            continue
        investigated_ips.add(ip)
        rec = active_provider.investigate_ip(ip)
        ip_records.append(rec)
        limitations.extend(rec.limitations)

    # 3. Investigate URLs
    investigated_urls: set[str] = set()
    for u in ioc_bundle.urls:
        if not u or u in investigated_urls:
            continue
        investigated_urls.add(u)
        rec = active_provider.investigate_url(u)
        url_records.append(rec)
        limitations.extend(rec.limitations)

    # Deduplicate limitations
    unique_limitations = list(dict.fromkeys(limitations))

    return OSINTAnalysisResult(
        domains=domain_records,
        ips=ip_records,
        urls=url_records,
        data_source=provider_name,
        limitations=unique_limitations,
    )
