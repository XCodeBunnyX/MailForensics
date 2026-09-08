"""
GmailGuard — Authentication Analyzer

Parses the Authentication-Results header and individual SPF/DKIM/DMARC
headers to extract authentication outcomes.

Outcomes: PASS | FAIL | SOFTFAIL | NONE | UNKNOWN | NEUTRAL | PERMERROR | TEMPERROR

Rules:
  - PASS  → positive evidence (reduces risk contribution)
  - FAIL  → negative evidence (increases risk contribution)
  - NONE / UNKNOWN → neutral (missing info ≠ malicious)
  - A PASS on all three does NOT guarantee the email is safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .email_parser import ParsedEmail

# ── Valid result tokens ──────────────────────────────────────────
_VALID_RESULTS = {
    "pass", "fail", "softfail", "none", "neutral",
    "permerror", "temperror", "hardfail",
}

# Normalize aliases
_NORMALIZE_MAP = {
    "hardfail": "FAIL",
    "pass":     "PASS",
    "fail":     "FAIL",
    "softfail": "SOFTFAIL",
    "none":     "NONE",
    "neutral":  "NEUTRAL",
    "permerror":"PERMERROR",
    "temperror":"TEMPERROR",
}


def _extract_result(header_val: str, protocol: str) -> str:
    """
    Extract the result for a specific protocol from an
    Authentication-Results header string.

    Examples of things we match:
      spf=pass
      dkim=fail
      dmarc=none
    """
    if not header_val:
        return "UNKNOWN"

    # Look for  <protocol>=<result>  pattern
    pattern = re.compile(
        rf'\b{re.escape(protocol)}\s*=\s*([\w]+)',
        re.IGNORECASE
    )
    match = pattern.search(header_val)
    if match:
        raw = match.group(1).lower()
        return _NORMALIZE_MAP.get(raw, "UNKNOWN")

    return "UNKNOWN"


def _parse_received_spf(spf_header: str) -> str:
    """
    Parse a Received-SPF header (alternative to Authentication-Results).
    e.g. 'Received-SPF: fail (...)' or 'Received-SPF: pass ...'
    """
    if not spf_header:
        return "UNKNOWN"
    match = re.match(r'\s*([\w]+)', spf_header.strip(), re.IGNORECASE)
    if match:
        raw = match.group(1).lower()
        return _NORMALIZE_MAP.get(raw, "UNKNOWN")
    return "UNKNOWN"


@dataclass
class AuthResult:
    """Authentication analysis result."""
    spf: str            # PASS / FAIL / SOFTFAIL / NONE / UNKNOWN / ...
    dkim: str
    dmarc: str

    spf_detail: str     # raw snippet for forensic display
    dkim_detail: str
    dmarc_detail: str

    all_passed: bool    # True only if ALL three are PASS
    any_failed: bool    # True if ANY of the three is FAIL / SOFTFAIL

    summary: str        # human-readable one-liner


def analyze_authentication(parsed: ParsedEmail) -> AuthResult:
    """
    Extract SPF, DKIM and DMARC outcomes from email headers.

    Priority order:
      1. Authentication-Results header (most common)
      2. Received-SPF header (fallback for SPF)
      3. Individual DKIM-Signature presence (basic check)

    Args:
        parsed: A ParsedEmail from email_parser.

    Returns:
        AuthResult with outcomes and summary.
    """
    auth_hdr = parsed.authentication_results
    all_headers = parsed.all_headers

    # ── SPF ─────────────────────────────────────────────────────
    spf = _extract_result(auth_hdr, "spf")
    if spf == "UNKNOWN":
        # Fallback: Received-SPF header
        received_spf = all_headers.get("received-spf", "")
        spf = _parse_received_spf(received_spf)

    # Extract detail snippet for forensic display
    spf_detail_match = re.search(
        r'spf\s*=\s*[\w]+\s*(?:\([^)]*\))?[^;]*',
        auth_hdr, re.IGNORECASE
    )
    spf_detail = spf_detail_match.group(0).strip() if spf_detail_match else spf

    # ── DKIM ────────────────────────────────────────────────────
    dkim = _extract_result(auth_hdr, "dkim")
    if dkim == "UNKNOWN":
        # If a DKIM-Signature header exists but Authentication-Results
        # doesn't tell us the result, we mark it NONE (present but unverified)
        if "dkim-signature" in all_headers:
            dkim = "NONE"

    dkim_detail_match = re.search(
        r'dkim\s*=\s*[\w]+\s*(?:\([^)]*\))?[^;]*',
        auth_hdr, re.IGNORECASE
    )
    dkim_detail = dkim_detail_match.group(0).strip() if dkim_detail_match else dkim

    # ── DMARC ───────────────────────────────────────────────────
    dmarc = _extract_result(auth_hdr, "dmarc")

    dmarc_detail_match = re.search(
        r'dmarc\s*=\s*[\w]+\s*(?:\([^)]*\))?[^;]*',
        auth_hdr, re.IGNORECASE
    )
    dmarc_detail = dmarc_detail_match.group(0).strip() if dmarc_detail_match else dmarc

    # ── Aggregate flags ─────────────────────────────────────────
    fail_set = {"FAIL", "SOFTFAIL", "PERMERROR"}
    pass_set = {"PASS"}

    all_passed = all(r in pass_set for r in (spf, dkim, dmarc))
    any_failed = any(r in fail_set for r in (spf, dkim, dmarc))

    # ── Summary ─────────────────────────────────────────────────
    parts = [f"SPF={spf}", f"DKIM={dkim}", f"DMARC={dmarc}"]
    if all_passed:
        summary = f"All authentication checks passed ({', '.join(parts)})."
    elif any_failed:
        failed = [p for r, p in zip([spf, dkim, dmarc], parts) if r in fail_set]
        summary = f"Authentication failure(s): {', '.join(failed)}."
    else:
        summary = f"Authentication: {', '.join(parts)}."

    # Important caveat
    if all_passed:
        summary += (
            " Note: authentication passing does NOT guarantee email is safe — "
            "an attacker can pass SPF/DKIM/DMARC on their own domain."
        )

    return AuthResult(
        spf=spf, dkim=dkim, dmarc=dmarc,
        spf_detail=spf_detail,
        dkim_detail=dkim_detail,
        dmarc_detail=dmarc_detail,
        all_passed=all_passed,
        any_failed=any_failed,
        summary=summary,
    )
