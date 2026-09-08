"""
GmailGuard — IP Intelligence

Extracts public IP addresses from email headers, validates them,
and fetches reputation data (mock or live).

Design rules:
  - Private / reserved / loopback IPs are silently ignored.
  - Missing IPs cause no error.
  - Unknown IPs return a NEUTRAL reputation (score 50), never malicious.
  - Clearly labels results as "observable mail infrastructure".
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

from . import config
from .email_parser import ParsedEmail
from .mock_data.ip_reputation import get_ip_reputation

# ── IP extraction regex ──────────────────────────────────────────
_IPV4_PATTERN = re.compile(
    r'\b((?:\d{1,3}\.){3}\d{1,3})\b'
)
_IPV6_BRACKETED = re.compile(
    r'\[([\da-fA-F:]+)\]'
)

# Private networks to ignore (loaded from config)
_PRIVATE_NETS: list[ipaddress._BaseNetwork] = []
for cidr in config.PRIVATE_IP_NETWORKS:
    try:
        _PRIVATE_NETS.append(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        pass


def _is_private(ip_str: str) -> bool:
    """Return True if IP is private, reserved, or loopback."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            return True
        for net in _PRIVATE_NETS:
            if addr in net:
                return True
        return False
    except ValueError:
        return True  # unparseable → treat as private/skip


def extract_public_ips(parsed: ParsedEmail) -> list[str]:
    """
    Extract all observable public IP addresses from email headers.
    Sources: Received headers, X-Originating-IP.

    Returns a de-duplicated list of public IP strings.
    """
    candidates: list[str] = []

    # From Received headers
    for hdr in parsed.received_headers:
        for m in _IPV4_PATTERN.finditer(hdr):
            candidates.append(m.group(1))
        for m in _IPV6_BRACKETED.finditer(hdr):
            candidates.append(m.group(1))

    # From X-Originating-IP
    if parsed.x_originating_ip:
        candidates.append(parsed.x_originating_ip)

    # De-duplicate, filter private
    seen: set[str] = set()
    public_ips: list[str] = []
    for ip in candidates:
        if ip not in seen and not _is_private(ip):
            seen.add(ip)
            public_ips.append(ip)

    return public_ips


@dataclass
class IPRecord:
    """Intelligence record for a single IP address."""
    ip: str
    reputation: str          # "malicious" | "suspicious" | "clean" | "unknown"
    reputation_score: int    # 0-100, higher = more malicious
    categories: list[str]    # threat categories from reputation provider
    source: str              # reputation data source label
    is_observable_infra: bool = True  # always True — these are relay IPs


@dataclass
class IPIntelligence:
    """Aggregated IP intelligence for an email."""
    public_ips: list[str]
    records: list[IPRecord]
    any_malicious: bool
    any_suspicious: bool
    max_reputation_score: int     # worst-case score across all IPs
    limitations: list[str]        # notes about what we can't observe


def analyze_ips(parsed: ParsedEmail) -> IPIntelligence:
    """
    Extract public IPs and fetch reputation for each.

    Args:
        parsed: A ParsedEmail from email_parser.

    Returns:
        IPIntelligence with per-IP records and aggregate flags.
    """
    limitations: list[str] = []
    public_ips = extract_public_ips(parsed)

    if not public_ips:
        limitations.append(
            "No observable public IP addresses found in headers. "
            "Gmail and some providers strip sender device IP for privacy."
        )

    records: list[IPRecord] = []
    for ip in public_ips:
        rep = get_ip_reputation(ip)
        records.append(IPRecord(
            ip=ip,
            reputation=rep["reputation"],
            reputation_score=rep["score"],
            categories=rep["categories"],
            source=rep["source"],
        ))

    any_malicious = any(r.reputation == "malicious" for r in records)
    any_suspicious = any(r.reputation == "suspicious" for r in records)
    max_score = max((r.reputation_score for r in records), default=50)

    # Always include forensic limitation note
    limitations.append(
        "Observable IPs represent mail relay infrastructure only — "
        "they do NOT indicate the sender's physical device location."
    )

    return IPIntelligence(
        public_ips=public_ips,
        records=records,
        any_malicious=any_malicious,
        any_suspicious=any_suspicious,
        max_reputation_score=max_score,
        limitations=limitations,
    )
