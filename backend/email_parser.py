"""
GmailGuard — Email Parser

Parses a raw RFC 5322 email string into a structured ParsedEmail dataclass.
Uses only the Python standard library `email` module — no external deps.
"""

from __future__ import annotations

import email
import email.policy
import quopri
import base64
from dataclasses import dataclass, field
from email.message import Message
from typing import Optional
import re


@dataclass
class Attachment:
    """Represents a single email attachment."""
    filename: str
    content_type: str          # MIME type (e.g. 'application/pdf')
    size_bytes: int
    extension: str             # lowercase, includes dot (e.g. '.pdf')
    content: Optional[bytes] = field(default=None, repr=False)


@dataclass
class ParsedEmail:
    """Structured representation of a parsed email message."""

    # ── Envelope / Routing ──────────────────────────────────────
    raw_from: str              # raw From header value
    sender_email: str          # extracted email address
    sender_name: str           # display name (may be empty)
    sender_domain: str         # domain part of sender_email
    reply_to: str              # Reply-To header (empty string if absent)
    to: list[str]              # recipient addresses
    cc: list[str]
    subject: str
    date: str                  # raw Date header value
    message_id: str

    # ── Headers ─────────────────────────────────────────────────
    received_headers: list[str]       # all Received: headers in order
    authentication_results: str       # raw Authentication-Results header
    x_originating_ip: str            # X-Originating-IP if present
    x_mailer: str                    # X-Mailer if present
    all_headers: dict[str, str]      # full header dict (lowercase keys)

    # ── Body ────────────────────────────────────────────────────
    text_body: str             # plain-text part (decoded)
    html_body: str             # HTML part (decoded)

    # ── Attachments ─────────────────────────────────────────────
    attachments: list[Attachment]

    # ── Parse metadata ──────────────────────────────────────────
    parse_errors: list[str]    # non-fatal issues encountered during parse
    charsets: list[str] = field(default_factory=list)


def _decode_part(part: Message) -> str:
    """Decode a message part's payload to a string."""
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _extract_address(raw: str) -> tuple[str, str]:
    """
    Split 'Display Name <email@domain.com>' into (name, email).
    Returns ('', raw) if no angle-bracket form found.
    """
    raw = (raw or "").strip()
    match = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>', raw)
    if match:
        return match.group(1).strip(), match.group(2).strip().lower()
    # Bare address
    addr = re.search(r'[\w.%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}', raw)
    if addr:
        return "", addr.group(0).lower()
    return "", raw.lower()


def _extract_domain(email_addr: str) -> str:
    """Extract domain from an email address string."""
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].lower().strip()
    return ""


def parse_email(raw_email: str) -> ParsedEmail:
    """
    Parse a raw email string and return a ParsedEmail dataclass.

    Args:
        raw_email: Full raw RFC 5322 email as a string.

    Returns:
        ParsedEmail with all extracted fields. Never raises — parse
        errors are collected in parse_errors.
    """
    parse_errors: list[str] = []

    try:
        msg: Message = email.message_from_string(
            raw_email, policy=email.policy.compat32
        )
    except Exception as exc:
        parse_errors.append(f"Failed to parse email structure: {exc}")
        # Return a mostly-empty ParsedEmail
        return ParsedEmail(
            raw_from="", sender_email="", sender_name="", sender_domain="",
            reply_to="", to=[], cc=[], subject="", date="", message_id="",
            received_headers=[], authentication_results="", x_originating_ip="",
            x_mailer="", all_headers={}, text_body=raw_email,
            html_body="", attachments=[], parse_errors=parse_errors,
        )

    # ── Build header dict (lowercase keys) ───────────────────────
    all_headers: dict[str, str] = {}
    for key in msg.keys():
        all_headers[key.lower()] = msg[key] or ""

    # ── From ────────────────────────────────────────────────────
    raw_from = all_headers.get("from", "")
    sender_name, sender_email = _extract_address(raw_from)
    sender_domain = _extract_domain(sender_email)

    # ── Reply-To ────────────────────────────────────────────────
    reply_to_raw = all_headers.get("reply-to", "")
    _, reply_to = _extract_address(reply_to_raw)

    # ── To / CC ─────────────────────────────────────────────────
    def split_addresses(header_val: str) -> list[str]:
        addrs = []
        for part in header_val.split(","):
            _, addr = _extract_address(part)
            if addr:
                addrs.append(addr)
        return addrs

    to_list = split_addresses(all_headers.get("to", ""))
    cc_list = split_addresses(all_headers.get("cc", ""))

    # ── Received headers (preserve order) ───────────────────────
    received_headers: list[str] = msg.get_all("Received") or []

    # ── Authentication-Results ───────────────────────────────────
    auth_results = all_headers.get("authentication-results", "")

    # ── X-Originating-IP, X-Mailer ──────────────────────────────
    x_orig_ip = all_headers.get("x-originating-ip", "")
    # Strip surrounding brackets if present
    x_orig_ip = x_orig_ip.strip().strip("[]").strip()
    x_mailer = all_headers.get("x-mailer", "")

    # ── Body extraction ─────────────────────────────────────────
    text_body = ""
    html_body = ""
    attachments: list[Attachment] = []

    charsets_seen: list[str] = []
    def _record_charset(cs: Optional[str]):
        if cs:
            clean = cs.lower().strip().strip("\"'")
            if clean and clean not in charsets_seen:
                charsets_seen.append(clean)

    _record_charset(msg.get_content_charset())

    if msg.is_multipart():
        for part in msg.walk():
            _record_charset(part.get_content_charset())
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")

            if "attachment" in disposition.lower() or part.get_filename():
                # Attachment
                filename = part.get_filename() or "unnamed"
                ext = ""
                if "." in filename:
                    ext = "." + filename.rsplit(".", 1)[-1].lower()
                try:
                    content = part.get_payload(decode=True) or b""
                except Exception as exc:
                    content = b""
                    parse_errors.append(f"Attachment decode error ({filename}): {exc}")

                attachments.append(Attachment(
                    filename=filename,
                    content_type=ctype,
                    size_bytes=len(content),
                    extension=ext,
                    content=content,
                ))

            elif ctype == "text/plain" and not text_body:
                text_body = _decode_part(part)

            elif ctype == "text/html" and not html_body:
                html_body = _decode_part(part)

    else:
        # Single-part message
        ctype = msg.get_content_type()
        if ctype == "text/html":
            html_body = _decode_part(msg)
        else:
            text_body = _decode_part(msg)

    return ParsedEmail(
        raw_from=raw_from,
        sender_email=sender_email,
        sender_name=sender_name,
        sender_domain=sender_domain,
        reply_to=reply_to,
        to=to_list,
        cc=cc_list,
        subject=all_headers.get("subject", ""),
        date=all_headers.get("date", ""),
        message_id=all_headers.get("message-id", ""),
        received_headers=received_headers,
        authentication_results=auth_results,
        x_originating_ip=x_orig_ip,
        x_mailer=x_mailer,
        all_headers=all_headers,
        text_body=text_body,
        html_body=html_body,
        attachments=attachments,
        parse_errors=parse_errors,
        charsets=charsets_seen,
    )
