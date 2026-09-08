"""
GmailGuard — IOC Extractor

Extracts, normalizes, and deduplicates Indicators of Compromise (IOCs)
from parsed email headers, body content, URLs, and network metadata.

Strict deduplication ensures that:
- Domains appearing across multiple URLs are investigated only once.
- Duplicate IPs across multiple Received headers are investigated only once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Optional

from .email_parser import ParsedEmail
from .url_analyzer import URLAnalysis
from .ip_intelligence import IPIntelligence


@dataclass
class IOCBundle:
    """Structured container for all deduplicated indicators in an email."""
    sender_domain: str
    domains: list[str]           # Deduplicated list of all domains (sender + URL domains)
    ips: list[str]               # Deduplicated list of public/observable infrastructure IPs
    urls: list[str]              # Deduplicated list of observed URLs
    email_domains: list[str]     # Deduplicated sender and reply-to domains


import ipaddress


def _is_ip(val: str) -> bool:
    """Return True if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def _extract_domain_from_url(url: str) -> str:
    """Safely extract the domain/hostname from a URL string."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path
        domain = netloc.split(":")[0].strip().lower()
        # Strip trailing dot if any
        return domain.rstrip(".")
    except Exception:
        return ""


def _extract_domain_from_email_addr(addr: str) -> str:
    """Extract domain from an email address string (e.g. user@domain.com -> domain.com)."""
    if not addr or "@" not in addr:
        return ""
    return addr.split("@")[-1].strip().lower().rstrip(">").rstrip(".")


def extract_iocs(
    parsed: ParsedEmail,
    url_analysis: Optional[URLAnalysis] = None,
    ip_intel: Optional[IPIntelligence] = None,
) -> IOCBundle:
    """
    Extract, validate, and deduplicate all IOCs from an email.

    Ensures no indicator is investigated redundantly.
    """
    domains_set: set[str] = set()
    email_domains_set: set[str] = set()
    ips_set: set[str] = set()
    urls_set: set[str] = set()

    # 1. Sender domain & Reply-To domain
    sender_dom = (parsed.sender_domain or "").strip().lower()
    if sender_dom:
        sender_dom = sender_dom.lstrip("@").rstrip(".")
        if _is_ip(sender_dom):
            ips_set.add(sender_dom)
        else:
            domains_set.add(sender_dom)
            email_domains_set.add(sender_dom)

    if parsed.reply_to:
        reply_dom = _extract_domain_from_email_addr(parsed.reply_to)
        if reply_dom:
            if _is_ip(reply_dom):
                ips_set.add(reply_dom)
            else:
                domains_set.add(reply_dom)
                email_domains_set.add(reply_dom)

    # 2. URLs and their parent domains
    if url_analysis:
        for u in url_analysis.all_urls:
            cleaned_url = u.strip()
            if cleaned_url:
                urls_set.add(cleaned_url)
                dom = _extract_domain_from_url(cleaned_url)
                if dom:
                    if _is_ip(dom):
                        ips_set.add(dom)
                    elif "." in dom:
                        domains_set.add(dom)

        # Also inspect findings in case all_urls had subtle differences
        for f in url_analysis.findings:
            cleaned_url = f.url.strip()
            if cleaned_url:
                urls_set.add(cleaned_url)
            if f.domain:
                dom = f.domain.strip().lower()
                if _is_ip(dom):
                    ips_set.add(dom)
                else:
                    domains_set.add(dom)

    # 3. IP addresses (observable infrastructure & public IPs)
    if ip_intel:
        for ip in ip_intel.public_ips:
            cleaned_ip = ip.strip()
            if cleaned_ip:
                ips_set.add(cleaned_ip)

        for rec in ip_intel.records:
            if rec.ip:
                cleaned_ip = rec.ip.strip()
                if cleaned_ip:
                    ips_set.add(cleaned_ip)

    # In case ip_intel was not provided, fallback to parsed headers
    if not ip_intel:
        if parsed.x_originating_ip:
            ips_set.add(parsed.x_originating_ip.strip())

    # Remove empty strings and ensure domains_set has no IPs
    domains_set = {d for d in domains_set if d and not _is_ip(d)}
    email_domains_set.discard("")
    ips_set.discard("")
    urls_set.discard("")

    # Sort for deterministic output
    return IOCBundle(
        sender_domain=sender_dom,
        domains=sorted(list(domains_set)),
        ips=sorted(list(ips_set)),
        urls=sorted(list(urls_set)),
        email_domains=sorted(list(email_domains_set)),
    )
