"""
GmailGuard — Header Analyzer

Analyzes SMTP / sending infrastructure from email headers.
Extracts the relay chain, identifies known cloud/hosting providers,
and provides forensic context about observable mail infrastructure.

NOTE: "observable mail infrastructure" ≠ "sender's physical location".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from email_parser import ParsedEmail


# ── Known provider fingerprints ──────────────────────────────────
# Maps lowercase hostname substring → provider label
_KNOWN_PROVIDERS: dict[str, str] = {
    "google.com":          "Google (Gmail/Workspace)",
    "googlemail.com":      "Google (Gmail)",
    "googleapis.com":      "Google APIs",
    "outlook.com":         "Microsoft (Outlook/365)",
    "hotmail.com":         "Microsoft (Hotmail)",
    "microsoft.com":       "Microsoft",
    "office365.us":        "Microsoft (Office 365 GovCloud)",
    "protection.outlook":  "Microsoft EOP",
    "amazonses.com":       "Amazon SES",
    "mailchimp.com":       "Mailchimp",
    "sendgrid.net":        "SendGrid",
    "mailgun.org":         "Mailgun",
    "postmarkapp.com":     "Postmark",
    "sparkpostmail.com":   "SparkPost",
    "mandrillapp.com":     "Mandrill (Mailchimp)",
    "yahoodns.net":        "Yahoo Mail",
    "yahoo.com":           "Yahoo",
    "mimecast.com":        "Mimecast (Security Gateway)",
    "pphosted.com":        "Proofpoint",
    "barracudanetworks.com": "Barracuda",
    "cloudflare.com":      "Cloudflare",
    "amazonaws.com":       "Amazon AWS",
    "azure.com":           "Microsoft Azure",
    "fastmail.com":        "Fastmail",
    "protonmail.ch":       "ProtonMail",
    "zoho.com":            "Zoho Mail",
}

# Regex to extract IPs from Received headers
_IP_PATTERN = re.compile(
    r'\b(?:'
    r'(?:\d{1,3}\.){3}\d{1,3}'    # IPv4
    r'|'
    r'\[[\da-fA-F:]+\]'            # IPv6 in brackets
    r')\b'
)

# Regex to extract hostname from Received header
_HOST_PATTERN = re.compile(
    r'from\s+([\w.\-]+)',
    re.IGNORECASE
)


@dataclass
class RelayHop:
    """Single hop in the SMTP relay chain."""
    raw: str                        # raw Received header
    from_host: str                  # sending host name
    by_host: str                    # receiving host name
    ip: Optional[str]               # extracted IP (may be None)
    provider: str                   # identified provider or "Unknown"


@dataclass
class HeaderIntelligence:
    """Results of header / infrastructure analysis."""
    relay_chain: list[RelayHop]
    x_originating_ip: str           # from X-Originating-IP (may be empty)
    x_mailer: str
    reply_to_differs: bool          # Reply-To differs from From domain
    reply_to_address: str
    sender_email: str
    sender_domain: str
    identified_providers: list[str] # unique identified provider names
    infrastructure_note: str        # human-readable forensic note
    warnings: list[str]             # non-fatal issues / anomalies noticed


def _identify_provider(host: str) -> str:
    """Return a known provider label for a hostname, or 'Unknown'."""
    host_lower = host.lower()
    for pattern, label in _KNOWN_PROVIDERS.items():
        if pattern in host_lower:
            return label
    return "Unknown"


def _extract_by_host(raw: str) -> str:
    """Extract the 'by' hostname from a Received header."""
    match = re.search(r'\bby\s+([\w.\-]+)', raw, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_first_ip(raw: str) -> Optional[str]:
    """Extract first IP address found in a Received header."""
    match = _IP_PATTERN.search(raw)
    if match:
        return match.group(0).strip("[]")
    return None


def analyze_headers(parsed: ParsedEmail) -> HeaderIntelligence:
    """
    Analyze SMTP relay chain and header anomalies.

    Args:
        parsed: A ParsedEmail dataclass from email_parser.

    Returns:
        HeaderIntelligence with relay chain, providers, and warnings.
    """
    warnings: list[str] = []
    relay_chain: list[RelayHop] = []
    seen_providers: list[str] = []

    for raw_header in parsed.received_headers:
        # Extract from-host
        from_match = _HOST_PATTERN.search(raw_header)
        from_host = from_match.group(1) if from_match else "unknown"

        by_host = _extract_by_host(raw_header)
        ip = _extract_first_ip(raw_header)
        provider = _identify_provider(from_host) if from_host != "unknown" else "Unknown"

        if provider != "Unknown" and provider not in seen_providers:
            seen_providers.append(provider)

        relay_chain.append(RelayHop(
            raw=raw_header.strip(),
            from_host=from_host,
            by_host=by_host,
            ip=ip,
            provider=provider,
        ))

    # ── X-Originating-IP provider check ─────────────────────────
    x_ip = parsed.x_originating_ip
    x_ip_note = ""
    if x_ip:
        x_ip_note = f" (from X-Originating-IP: {x_ip})"

    # ── Reply-To differs from From? ──────────────────────────────
    reply_to_differs = False
    reply_to_domain = ""
    if parsed.reply_to and parsed.sender_domain:
        if "@" in parsed.reply_to:
            reply_to_domain = parsed.reply_to.split("@", 1)[1].lower()
        if reply_to_domain and reply_to_domain != parsed.sender_domain.lower():
            reply_to_differs = True
            warnings.append(
                f"Reply-To domain '{reply_to_domain}' differs from "
                f"From domain '{parsed.sender_domain}' — possible social engineering."
            )

    # ── X-Mailer anomaly ────────────────────────────────────────
    suspicious_mailers = ["phpmailer", "the bat!", "sendinblue", "massmailer"]
    if parsed.x_mailer:
        for sm in suspicious_mailers:
            if sm.lower() in parsed.x_mailer.lower():
                warnings.append(
                    f"X-Mailer '{parsed.x_mailer}' is associated with bulk/automated sending."
                )
                break

    # ── Infrastructure note ─────────────────────────────────────
    hop_count = len(relay_chain)
    if hop_count == 0:
        infra_note = (
            "No Received headers found. This may indicate a locally composed "
            "message or headers were stripped."
        )
    else:
        providers_str = ", ".join(seen_providers) if seen_providers else "unidentified infrastructure"
        infra_note = (
            f"Email passed through {hop_count} observable relay hop(s) via {providers_str}."
            f"{x_ip_note} Note: observable IPs represent mail relay infrastructure, "
            "not necessarily the sender's physical location."
        )

    # Gmail-specific note
    if "Google (Gmail/Workspace)" in seen_providers or "Google (Gmail)" in seen_providers:
        infra_note += (
            " Gmail strips sender device IP from headers for privacy — "
            "the originating device IP is NOT observable."
        )

    return HeaderIntelligence(
        relay_chain=relay_chain,
        x_originating_ip=x_ip,
        x_mailer=parsed.x_mailer,
        reply_to_differs=reply_to_differs,
        reply_to_address=parsed.reply_to,
        sender_email=parsed.sender_email,
        sender_domain=parsed.sender_domain,
        identified_providers=seen_providers,
        infrastructure_note=infra_note,
        warnings=warnings,
    )
