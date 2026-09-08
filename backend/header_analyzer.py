"""
GmailGuard — Header Analyzer

Analyzes SMTP / sending infrastructure from email headers.
Extracts the relay chain, identifies known cloud/hosting providers,
and provides forensic context about observable mail infrastructure.

NOTE: "observable mail infrastructure" ≠ "sender's physical location".
"""

import email.utils
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from . import config
from .email_parser import ParsedEmail


@dataclass
class ClientFingerprint:
    """Client & environment fingerprint inferred from headers, boundaries, and charsets."""
    mailer: str = "Not specified"
    mailer_category: str = "Unknown"        # "Programmatic / Automated Sender" | "Desktop Client" | "Webmail Interface" | "Marketing / Bulk Platform" | "Standard / Unknown"
    user_agent: str = "Not specified"
    mime_boundary_style: str = "None"       # "Outlook MAPI" | "PHPMailer" | "Python smtplib" | "Generic Multipart" | "None"
    charsets_detected: list[str] = field(default_factory=list)
    languages_detected: list[str] = field(default_factory=list)
    fingerprint_summary: str = "Standard email headers"
    evidence_class: str = "HEURISTIC"
    charset_disclaimer: str = (
        "Character encoding represents byte serialization format and operating system defaults; "
        "it does not indicate sender nationality or geographic location."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mailer": self.mailer,
            "mailer_category": self.mailer_category,
            "user_agent": self.user_agent,
            "mime_boundary_style": self.mime_boundary_style,
            "charsets_detected": self.charsets_detected,
            "languages_detected": self.languages_detected,
            "fingerprint_summary": self.fingerprint_summary,
            "evidence_class": self.evidence_class,
            "charset_disclaimer": self.charset_disclaimer,
        }


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
    """Single hop in the SMTP relay chain with granular evidence taxonomy."""
    raw: str                             # OBSERVED: Raw Received header string
    from_host: str                       # DERIVED: Sending host name
    by_host: str                         # DERIVED: Receiving host name
    ip: Optional[str]                    # DERIVED: Extracted IP (may be None)
    provider: str                        # DERIVED: Identified provider or "Unknown"
    hop_number: int = 1                  # DERIVED: Chronological hop order (1 = earliest)
    is_private: bool = False             # DERIVED: True if IP is private/loopback/LAN
    timestamp_raw: Optional[str] = None  # OBSERVED: Raw timestamp string from Received header
    timestamp_utc: Optional[str] = None  # DERIVED: UTC-normalized ISO 8601 timestamp string
    timestamp_dt: Optional[datetime] = None  # DERIVED: UTC datetime object for delta calculations
    provenance: str = "UNKNOWN"          # DERIVED: RECIPIENT_MTA_OBSERVED | UPSTREAM_MTA_RECORDED | UNVERIFIED_UPSTREAM_HOP | CLIENT_OR_HEADER_SUPPLIED
    confidence: str = "medium"           # DERIVED: high | medium | low
    is_upstream_origin: bool = False     # DERIVED: True if selected as primary candidate
    evidence_class: str = "DERIVED"      # DERIVED: (Note: .raw is OBSERVED, parsed properties are DERIVED)


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
    upstream_relay_ip: Optional[str] = None
    chronological_hops: list[RelayHop] = field(default_factory=list)
    client_fingerprint: Optional[ClientFingerprint] = None
    candidate_relays: list[dict[str, Any]] = field(default_factory=list)
    timeline_analysis: dict[str, Any] = field(default_factory=dict)


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


def _is_private_ip(ip_str: Optional[str]) -> bool:
    """Return True if IP is private, reserved, loopback, link-local, multicast, or invalid (IPv4 or IPv6)."""
    if not ip_str or not isinstance(ip_str, str):
        return True
    clean_ip = ip_str.strip().strip("[]")
    try:
        addr = ipaddress.ip_address(clean_ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local or addr.is_multicast:
            return True
        for net_str in getattr(config, "PRIVATE_IP_NETWORKS", []):
            try:
                if addr in ipaddress.ip_network(net_str, strict=False):
                    return True
            except ValueError:
                continue
        return False
    except ValueError:
        return True


def _extract_received_timestamp(raw_header: str) -> tuple[Optional[str], Optional[datetime], Optional[str]]:
    """
    Extract timestamp from Received header, convert to UTC datetime and ISO string.
    Returns (raw_timestamp_str, utc_datetime, utc_iso_str).
    """
    if ";" not in raw_header:
        return None, None, None
    raw_ts = raw_header.rsplit(";", 1)[1].strip()
    clean_ts = re.sub(r'\(.*?\)', '', raw_ts).strip()
    try:
        dt = email.utils.parsedate_to_datetime(clean_ts)
        if dt.tzinfo is not None:
            utc_dt = dt.astimezone(timezone.utc)
        else:
            utc_dt = dt.replace(tzinfo=timezone.utc)
        return raw_ts, utc_dt, utc_dt.isoformat()
    except Exception:
        return raw_ts if raw_ts else None, None, None


def _determine_hop_provenance(raw_header: str, is_recipient_mta: bool) -> tuple[str, str]:
    """
    Determine hop trust provenance and confidence based on evidence in header.
    Returns (provenance_str, confidence_str).
    """
    if is_recipient_mta:
        return "RECIPIENT_MTA_OBSERVED", "high"
    # Check if header contains authenticating MTA transfer clauses
    has_mta_clauses = bool(re.search(
        r'\bby\s+[\w.\-]+\s+(?:with\s+[\w.\-]+|via\s+[\w.\-]+|id\s+[\w.\-]+|;)',
        raw_header,
        re.IGNORECASE
    ))
    if has_mta_clauses:
        return "UPSTREAM_MTA_RECORDED", "medium"
    return "UNVERIFIED_UPSTREAM_HOP", "low"


def _extract_client_fingerprint(parsed: ParsedEmail) -> ClientFingerprint:
    """Extract and classify client MUA, boundary formats, and charsets neutrally."""
    raw_mailer = (parsed.x_mailer or parsed.all_headers.get("user-agent") or parsed.all_headers.get("x-agent") or "").strip()
    mailer_lower = raw_mailer.lower()

    mailer_category = "Standard / Unknown"
    if raw_mailer:
        if any(s in mailer_lower for s in [
            "phpmailer", "python", "smtplib", "sendinblue", "massmailer", "curl",
            "libwww", "the bat!", "lwp", "perl", "go-http", "java", "ruby",
            "mailer daemon", "swiftmailer"
        ]):
            mailer_category = "Programmatic / Automated Sender"
        elif any(s in mailer_lower for s in ["outlook", "microsoft office", "thunderbird", "apple mail", "eudora", "lotus notes"]):
            mailer_category = "Desktop Client"
        elif any(s in mailer_lower for s in ["roundcube", "squirrelmail", "horde", "zimbra", "webmail"]):
            mailer_category = "Webmail Interface"
        elif any(s in mailer_lower for s in ["mailchimp", "sendgrid", "hubspot", "marketo", "constant contact"]):
            mailer_category = "Marketing / Bulk Platform"

    boundary_style = "None"
    content_type = parsed.all_headers.get("content-type", "")
    boundary_match = re.search(r'boundary=["\']?([^"\';\s]+)["\']?', content_type, re.IGNORECASE)
    if boundary_match:
        b_val = boundary_match.group(1)
        if "_NextPart_" in b_val or "----=_NextPart" in b_val:
            boundary_style = "Outlook MAPI"
        elif b_val.startswith("b1_") or b_val.startswith("b2_"):
            boundary_style = "PHPMailer"
        elif b_val.startswith("===") or b_val.startswith("===="):
            boundary_style = "Python smtplib"
        elif b_val.startswith("------------"):
            boundary_style = "Thunderbird"
        elif b_val.startswith("_----------=_"):
            boundary_style = "Perl MIME::Lite"
        else:
            boundary_style = "Generic Multipart"

    charsets: list[str] = list(getattr(parsed, "charsets", []))
    for header_key, header_val in parsed.all_headers.items():
        for cm in re.finditer(r'charset=["\']?([a-zA-Z0-9\-_]+)["\']?', header_val, re.IGNORECASE):
            c = cm.group(1).lower()
            if c not in charsets:
                charsets.append(c)

    # Only inspect Content-Language (do not depend on non-standard Accept-Language)
    languages: list[str] = []
    if "content-language" in parsed.all_headers:
        for lang in re.split(r'[,;]', parsed.all_headers["content-language"]):
            clean_lang = lang.strip().lower()
            if clean_lang and not clean_lang.startswith("q=") and clean_lang not in languages:
                languages.append(clean_lang)

    summary_parts: list[str] = []
    if raw_mailer:
        summary_parts.append(f"{mailer_category} ('{raw_mailer}')")
    else:
        summary_parts.append("No explicit MUA declared")
    if boundary_style != "None":
        summary_parts.append(f"MIME pattern: {boundary_style}")
    if charsets:
        summary_parts.append(f"Charsets: {', '.join(charsets)}")
    if languages:
        summary_parts.append(f"Content-Lang: {', '.join(languages)}")

    summary = "; ".join(summary_parts)

    return ClientFingerprint(
        mailer=raw_mailer or "Not specified",
        mailer_category=mailer_category,
        user_agent=parsed.all_headers.get("user-agent", "Not specified"),
        mime_boundary_style=boundary_style,
        charsets_detected=charsets,
        languages_detected=languages,
        fingerprint_summary=summary,
    )


def _extract_first_ip(raw: str) -> Optional[str]:
    """Extract first IP address found in a Received header."""
    match = _IP_PATTERN.search(raw)
    if match:
        return match.group(0).strip("[]")
    return None


def analyze_headers(parsed: ParsedEmail) -> HeaderIntelligence:
    """
    Analyze SMTP relay chain, evaluate observational provenance, normalize timestamps to UTC,
    rank candidate relays, and perform timeline skew analysis.

    Args:
        parsed: A ParsedEmail dataclass from email_parser.

    Returns:
        HeaderIntelligence with relay chain, chronological hops, candidate relays,
        timeline analysis, client fingerprint, and provider warnings.
    """
    warnings: list[str] = []
    relay_chain: list[RelayHop] = []
    seen_providers: list[str] = []

    # 1. Parse Received headers in order of appearance (top to bottom)
    # The first header (index 0) was directly recorded by the recipient MTA.
    for idx, raw_header in enumerate(parsed.received_headers):
        is_recipient_mta = (idx == 0)
        from_match = _HOST_PATTERN.search(raw_header)
        from_host = from_match.group(1) if from_match else "unknown"

        by_host = _extract_by_host(raw_header)
        ip = _extract_first_ip(raw_header)
        provider = _identify_provider(from_host) if from_host != "unknown" else "Unknown"

        if provider != "Unknown" and provider not in seen_providers:
            seen_providers.append(provider)

        raw_ts, ts_dt, ts_utc = _extract_received_timestamp(raw_header)
        prov, conf = _determine_hop_provenance(raw_header, is_recipient_mta)

        relay_chain.append(RelayHop(
            raw=raw_header.strip(),
            from_host=from_host,
            by_host=by_host,
            ip=ip,
            provider=provider,
            is_private=_is_private_ip(ip) if ip else False,
            timestamp_raw=raw_ts,
            timestamp_utc=ts_utc,
            timestamp_dt=ts_dt,
            provenance=prov,
            confidence=conf,
            evidence_class="DERIVED",
        ))

    # 2. Chronological Hop Analysis (bottom-to-top traversal)
    # In RFC 5321/5322, bottom Received header is earliest sender hop; top is recipient MX.
    chronological_raw = list(reversed(parsed.received_headers))
    chronological_hops: list[RelayHop] = []
    total_hops = len(chronological_raw)

    for hop_idx, raw_header in enumerate(chronological_raw, start=1):
        is_recipient_mta = (hop_idx == total_hops)
        from_match = _HOST_PATTERN.search(raw_header)
        from_host = from_match.group(1) if from_match else "unknown"
        by_host = _extract_by_host(raw_header)
        ip = _extract_first_ip(raw_header)
        provider = _identify_provider(from_host) if from_host != "unknown" else "Unknown"
        is_priv = _is_private_ip(ip) if ip else False

        raw_ts, ts_dt, ts_utc = _extract_received_timestamp(raw_header)
        prov, conf = _determine_hop_provenance(raw_header, is_recipient_mta)

        hop = RelayHop(
            raw=raw_header.strip(),
            from_host=from_host,
            by_host=by_host,
            ip=ip,
            provider=provider,
            hop_number=hop_idx,
            is_private=is_priv,
            timestamp_raw=raw_ts,
            timestamp_utc=ts_utc,
            timestamp_dt=ts_dt,
            provenance=prov,
            confidence=conf,
            is_upstream_origin=False,
            evidence_class="DERIVED",
        )
        chronological_hops.append(hop)

    # 3. Candidate Relays Ranking Hierarchy
    # Tier 1: RECIPIENT_MTA_OBSERVED public IP
    # Tier 2: UPSTREAM_MTA_RECORDED public IP
    # Tier 3: UNVERIFIED_UPSTREAM_HOP public IP
    # Tier 4: CLIENT_OR_HEADER_SUPPLIED public IP (X-Originating-IP)
    candidate_relays: list[dict[str, Any]] = []
    seen_candidate_ips: set[str] = set()

    for hop in chronological_hops:
        if hop.ip and not hop.is_private and hop.ip not in seen_candidate_ips:
            seen_candidate_ips.add(hop.ip)
            tier_num = 1 if hop.provenance == "RECIPIENT_MTA_OBSERVED" else (2 if hop.provenance == "UPSTREAM_MTA_RECORDED" else 3)
            candidate_relays.append({
                "ip": hop.ip,
                "tier": tier_num,
                "tier_name": hop.provenance,
                "confidence": hop.confidence,
                "source_header": "Received",
                "hop_number": hop.hop_number,
                "provider": hop.provider,
                "ranking_disclaimer": "Ranking reflects observational proximity and trust boundaries, NOT definitive proof of sender origin.",
            })

    x_ip = parsed.x_originating_ip.strip() if parsed.x_originating_ip else ""
    x_ip_note = ""
    if x_ip:
        x_ip_note = f" (from X-Originating-IP: {x_ip})"
        if not _is_private_ip(x_ip) and x_ip not in seen_candidate_ips:
            seen_candidate_ips.add(x_ip)
            candidate_relays.append({
                "ip": x_ip,
                "tier": 4,
                "tier_name": "CLIENT_OR_HEADER_SUPPLIED",
                "confidence": "low",
                "source_header": "X-Originating-IP",
                "hop_number": None,
                "provider": _identify_provider(x_ip),
                "ranking_disclaimer": "Header-supplied IP is untrusted and may be spoofed; does not outrank Received: headers.",
            })

    # Sort candidates by Tier ascending (Tier 1 > Tier 2 > Tier 3 > Tier 4)
    candidate_relays.sort(key=lambda c: c["tier"])

    # For backward compatibility, designate primary upstream candidate
    upstream_relay_ip = candidate_relays[0]["ip"] if candidate_relays else None
    if upstream_relay_ip:
        for hop in chronological_hops:
            if hop.ip == upstream_relay_ip:
                hop.is_upstream_origin = True
                break

    # 4. Hop Timeline Skew & UTC Latency Analysis
    timeline_anomalies: list[dict[str, Any]] = []
    hop_deltas: list[dict[str, Any]] = []
    tolerance = getattr(config, "TIMESTAMP_SKEW_TOLERANCE_SECONDS", 120)

    for i in range(1, len(chronological_hops)):
        prev_h = chronological_hops[i - 1]
        curr_h = chronological_hops[i]
        if prev_h.timestamp_dt and curr_h.timestamp_dt:
            delta_sec = (curr_h.timestamp_dt - prev_h.timestamp_dt).total_seconds()
            hop_deltas.append({
                "from_hop": prev_h.hop_number,
                "to_hop": curr_h.hop_number,
                "delta_seconds": round(delta_sec, 2),
            })
            if delta_sec < -tolerance:
                anomaly_desc = (
                    f"Hop {curr_h.hop_number} timestamp appears {abs(delta_sec):.0f}s earlier than "
                    f"hop {prev_h.hop_number} (exceeding {tolerance}s skew tolerance). "
                    "Possible clock skew, mail queuing delay, or altered header timestamps."
                )
                timeline_anomalies.append({
                    "from_hop": prev_h.hop_number,
                    "to_hop": curr_h.hop_number,
                    "delta_seconds": round(delta_sec, 2),
                    "tolerance_seconds": tolerance,
                    "type": "TIMESTAMP_SKEW_OBSERVED",
                    "description": anomaly_desc,
                })
                warnings.append(f"Relay timeline anomaly: {anomaly_desc}")

    timeline_status = "consistent"
    if timeline_anomalies:
        timeline_status = "skew_observed"
    elif not hop_deltas:
        timeline_status = "unparseable"

    timeline_analysis = {
        "status": timeline_status,
        "tolerance_seconds": tolerance,
        "hop_deltas": hop_deltas,
        "anomalies": timeline_anomalies,
    }

    # 5. Client & Environment Fingerprinting
    client_fp = _extract_client_fingerprint(parsed)

    # 6. Reply-To differs from From?
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

    # 7. Infrastructure note
    hop_count = len(relay_chain)
    if hop_count == 0:
        infra_note = (
            "No Received headers found. This may indicate a locally composed "
            "message or headers were stripped."
        )
    else:
        providers_str = ", ".join(seen_providers) if seen_providers else "unidentified infrastructure"
        upstream_str = f" Primary observed relay IP: {upstream_relay_ip}." if upstream_relay_ip else ""
        infra_note = (
            f"Email passed through {hop_count} observable relay hop(s) via {providers_str}.{upstream_str}"
            f"{x_ip_note} Note: observable IPs represent mail relay infrastructure, "
            "not the sender's physical location."
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
        upstream_relay_ip=upstream_relay_ip,
        chronological_hops=chronological_hops,
        client_fingerprint=client_fp,
        candidate_relays=candidate_relays,
        timeline_analysis=timeline_analysis,
    )
