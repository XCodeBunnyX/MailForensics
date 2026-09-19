"""
GmailGuard — Deep Attachment Content Analyzer

Safely inspects the internal contents, object structure, and payloads of
email attachments (supporting PDF, Office OOXML, Archives, and Text documents).

CRITICAL SECURITY PRINCIPLES:
  - Attachments are NEVER executed on the host.
  - No dynamic execution or sandboxing is performed in this layer.
  - Passwords are NEVER bypassed or cracked.
  - Password-protected/encrypted documents are reported as LIMITED / NOT ANALYZABLE;
    they are NEVER assumed safe simply because they are locked.
  - The verdict for unflagged files is NO_THREATS_DETECTED ("no suspicious indicators
    detected by this analyzer"), NOT "SAFE", recognizing that static/content inspection
    cannot mathematically prove absence of all zero-day threats.
  - Extracted URLs and domains are treated as untrusted input and forwarded to the
    existing URL/domain intelligence pipeline without duplicate reputation logic.
  - Malformed or corrupted files fail gracefully with diagnostic limits and
    never crash the email analysis pipeline.
"""

from __future__ import annotations

import base64
import io
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import pypdf
    from pypdf.errors import PyPdfError
    _PYPDF_AVAILABLE = True
except ImportError:
    pypdf = None
    PyPdfError = Exception
    _PYPDF_AVAILABLE = False

from . import config
from .email_parser import Attachment


# ── URL extraction regex for document text & streams ───────────────
_DOC_URL_REGEX = re.compile(
    r'https?://[^\s\'"<>\[\](){}|\\^`]+'
    r'|'
    r'www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s\'"<>\[\](){}|\\^`]*',
    re.IGNORECASE,
)

_IP_URL_REGEX = re.compile(
    r'https?://(\d{1,3}\.){3}\d{1,3}',
    re.IGNORECASE,
)


def _clean_and_normalize_url(url: str) -> str:
    """Normalize extracted URL, stripping punctuation and unquoting percent-encodings."""
    cleaned = (url or "").strip().rstrip(".,;:)'\"\\>]}")
    if cleaned.lower().startswith("www."):
        cleaned = "http://" + cleaned
    # Normalize percent-encoded sequences if safe
    try:
        if "%" in cleaned:
            # Unquote harmless characters while preserving structure
            cleaned = urllib.parse.unquote(cleaned)
    except Exception:
        pass
    return cleaned


def _is_valid_url(url: str) -> bool:
    """
    Verify if a candidate string is a structurally valid URL.
    Must have http/https scheme, a valid non-empty host with at least one dot or localhost/IP,
    and no disallowed control or whitespace characters.
    """
    if not url or not isinstance(url, str):
        return False
    cleaned = url.strip()
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        return False
    try:
        parsed = urllib.parse.urlparse(cleaned)
        netloc = parsed.netloc.split(":")[0].strip()
        if not netloc or len(netloc) < 3:
            return False
        # Host must contain a dot or be valid IP/localhost
        if "." not in netloc and netloc.lower() not in ("localhost", "127.0.0.1"):
            return False
        # Disallow spaces or control characters in netloc
        if any(c.isspace() for c in netloc):
            return False
        return True
    except Exception:
        return False


def _extract_domain_from_url(url: str) -> str:
    """Safely extract netloc/domain from URL string."""
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        return parsed.netloc.lower().split(":")[0].strip()
    except Exception:
        return ""


_REDIRECT_PARAMS = {
    "url", "q", "target", "dest", "destination", "redirect",
    "redirect_url", "link", "r", "u", "goto", "uri", "next"
}


def _unwrap_redirect_url(url: str) -> list[str]:
    """
    Unwrap redirect / wrapper URLs such as google.com/goto?url=... or safelinks.
    Extracts underlying destination target URLs when possible.
    """
    if not url:
        return []

    unwrapped: list[str] = []
    cleaned_url = _clean_and_normalize_url(url)

    try:
        parsed = urllib.parse.urlparse(cleaned_url if "://" in cleaned_url else "http://" + cleaned_url)
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)

        # 1. Inspect common redirect parameter keys
        for param_name, param_values in query_params.items():
            if param_name.lower() in _REDIRECT_PARAMS:
                for val in param_values:
                    val_str = val.strip()
                    if not val_str:
                        continue

                    cand = val_str
                    if "%" in cand:
                        cand = urllib.parse.unquote(cand).strip()

                    if cand.lower().startswith(("http://", "https://", "www.")):
                        norm = _clean_and_normalize_url(cand)
                        if norm and norm not in unwrapped and norm != cleaned_url and _is_valid_url(norm):
                            unwrapped.append(norm)
                        continue

                    # Attempt Base64 decode (e.g. for encoded target URLs)
                    if len(val_str) >= 8 and re.match(r'^[A-Za-z0-9+/=_-]+$', val_str):
                        try:
                            b64_cand = val_str.replace("-", "+").replace("_", "/")
                            padded = b64_cand + "=" * ((4 - len(b64_cand) % 4) % 4)
                            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore").strip()
                            if decoded.lower().startswith(("http://", "https://", "www.")):
                                norm = _clean_and_normalize_url(decoded)
                                if norm and norm not in unwrapped and norm != cleaned_url and _is_valid_url(norm):
                                    unwrapped.append(norm)
                        except Exception:
                            pass

        # 2. Proofpoint URL defense inspection (urldefense.com/v3/__https://...__)
        if "urldefense." in parsed.netloc.lower():
            match = re.search(r'__(https?://[^_]+)__', cleaned_url)
            if match:
                norm = _clean_and_normalize_url(match.group(1))
                if norm and norm not in unwrapped and norm != cleaned_url and _is_valid_url(norm):
                    unwrapped.append(norm)

        # 3. Path-embedded redirect (e.g. /https://evil.com or /link/http://evil.com)
        path = parsed.path
        if "http://" in path or "https://" in path:
            match = re.search(r'(https?://[^\s\'"<>\[\](){}|\\^`]+)', path)
            if match:
                norm = _clean_and_normalize_url(match.group(1))
                if norm and norm not in unwrapped and norm != cleaned_url and _is_valid_url(norm):
                    unwrapped.append(norm)

    except Exception:
        pass

    return unwrapped


def _extract_pdf_urls(
    annot_uris: list[str],
    text_chunks: list[str],
    structural_uris: Optional[list[str]] = None,
) -> list[str]:
    """
    Extract, reassemble line-wrapped fragments, and deduplicate URLs from PDF documents.
    Prioritizes authoritative PDF hyperlink annotations (/URI), handles line-wrapped URLs
    in visible text, and suppresses partial fragments so each URL target is represented once.
    """
    primary_urls: list[str] = []
    seen_primary: set[str] = set()

    for u in (annot_uris or []) + (structural_uris or []):
        norm = _clean_and_normalize_url(u)
        if norm and _is_valid_url(norm) and norm not in seen_primary:
            seen_primary.add(norm)
            primary_urls.append(norm)

    # Reassemble line-wrapped URLs in extracted text
    text_candidates: list[str] = []
    for chunk in text_chunks:
        if not chunk or not chunk.strip():
            continue
        lines = chunk.splitlines()
        joined_lines: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            # Check if line ends with a URL fragment and the next line continues it
            while i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if line and ("http://" in line or "https://" in line) and not line.endswith((" ", ".", ";", "!", "?")):
                    # Next line continues with URL characters without spaces or starting a new word
                    if next_line and re.match(r'^[A-Za-z0-9_\-.~%!$&\'()*+,;=/?#]+$', next_line):
                        line = line + next_line
                        i += 1
                        continue
                break
            joined_lines.append(line)
            i += 1

        rejoined_text = " \n ".join(joined_lines)
        for m in _DOC_URL_REGEX.finditer(rejoined_text):
            cand_norm = _clean_and_normalize_url(m.group(0))
            if cand_norm and _is_valid_url(cand_norm):
                text_candidates.append(cand_norm)

    # Suppress fragments that are strict substrings or prefixes of annotations or longer candidates
    filtered_candidates: list[str] = []
    seen_all: set[str] = set(seen_primary)

    for cand in text_candidates:
        if cand in seen_all:
            continue
        # If candidate is a strict prefix or substring of any annotation URL, it is a wrapped fragment
        is_fragment = False
        for p in primary_urls:
            if cand != p and cand in p:
                is_fragment = True
                break
        if is_fragment:
            continue

        # If candidate is a strict prefix/substring of any longer text candidate
        for other in text_candidates:
            if cand != other and cand in other and len(cand) < len(other):
                is_fragment = True
                break
        if not is_fragment and cand not in seen_all:
            seen_all.add(cand)
            filtered_candidates.append(cand)

    return primary_urls + filtered_candidates


def _process_extracted_urls(raw_urls: list[str]) -> tuple[list[str], list[str]]:
    """
    Normalize, unwrap redirect wrappers, and deduplicate extracted URLs.
    Extracts associated unique parent domains.
    Filters out line-wrapped fragments and malformed URLs.
    """
    normalized_urls: list[str] = []
    seen_urls: set[str] = set()
    domains: list[str] = []
    seen_domains: set[str] = set()

    for raw_u in raw_urls:
        if not raw_u:
            continue
        cleaned = _clean_and_normalize_url(raw_u)
        if not cleaned or not _is_valid_url(cleaned):
            continue

        # Add normalized original URL
        if cleaned not in seen_urls:
            seen_urls.add(cleaned)
            normalized_urls.append(cleaned)

        # Attempt to unwrap redirect/wrapper URLs (e.g. google.com/goto?url=...)
        unwrapped_dests = _unwrap_redirect_url(cleaned)
        for dest in unwrapped_dests:
            if dest and _is_valid_url(dest) and dest not in seen_urls:
                seen_urls.add(dest)
                normalized_urls.append(dest)

    # Discard line-wrapped prefix fragments: only discard if u is a strict prefix of longer
    # (e.g. a line-wrapped path truncation like https://example.com/foo when https://example.com/foo/bar exists),
    # but never discard unwrapped redirect destinations which have different domains.
    final_urls: list[str] = []
    for u in normalized_urls:
        is_truncated_prefix = False
        for longer in normalized_urls:
            if u != longer and len(u) < len(longer) and longer.startswith(u):
                is_truncated_prefix = True
                break
        if not is_truncated_prefix:
            final_urls.append(u)

    for u in final_urls:
        d = _extract_domain_from_url(u)
        if d and d not in seen_domains:
            seen_domains.add(d)
            domains.append(d)

    return final_urls, domains


@dataclass
class AttachmentContentFinding:
    """Detailed content inspection finding for a single attachment."""
    filename: str
    file_type: str                      # "PDF", "OFFICE", "PLAIN_TEXT", "ARCHIVE", "UNKNOWN"
    content_analysis_status: str        # "ANALYZED", "LIMITED", "FALLBACK_SCAN", "FAILED", "UNSUPPORTED"
    content_analyzable: bool
    encrypted: bool
    reason: Optional[str] = None

    pages: int = 0
    text_extracted: bool = False
    text_length: int = 0
    text_preview: str = ""

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)

    javascript_detected: bool = False
    javascript_details: list[str] = field(default_factory=list)

    embedded_files: list[str] = field(default_factory=list)
    forms_detected: bool = False
    actions_detected: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)
    suspicious_indicators: list[str] = field(default_factory=list)

    content_risk_score: int = 0         # 0-100 (Heuristic rule-based score)
    content_verdict: str = "UNKNOWN"     # "NO_THREATS_DETECTED", "SUSPICIOUS", "HIGH_RISK", "UNKNOWN", "NOT_ANALYZABLE"
    reasons: list[str] = field(default_factory=list)

    extracted_iocs: dict[str, list[str]] = field(default_factory=lambda: {"urls": [], "domains": []})
    url_intelligence: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "file_type": self.file_type,
            "content_analysis_status": self.content_analysis_status,
            "status": self.content_analysis_status,
            "content_analyzable": self.content_analyzable,
            "encrypted": self.encrypted,
            "reason": self.reason,
            "pages": self.pages,
            "text_extracted": self.text_extracted,
            "text_length": self.text_length,
            "text_preview": self.text_preview,
            "urls": self.urls,
            "domains": self.domains,
            "javascript_detected": self.javascript_detected,
            "javascript_details": self.javascript_details,
            "embedded_files": self.embedded_files,
            "forms_detected": self.forms_detected,
            "actions_detected": self.actions_detected,
            "metadata": self.metadata,
            "suspicious_indicators": self.suspicious_indicators,
            "content_risk_score": self.content_risk_score,
            "content_verdict": self.content_verdict,
            "verdict": self.content_verdict,
            "reasons": self.reasons,
            "extracted_iocs": self.extracted_iocs,
            "url_intelligence": self.url_intelligence,
            "timeline": self.timeline,
        }


@dataclass
class AttachmentContentAnalysis:
    """Aggregate attachment content analysis result."""
    total_count: int
    analyzed_count: int
    limited_count: int
    failed_count: int
    findings: list[AttachmentContentFinding]

    def get_all_urls(self) -> list[str]:
        """Collect all de-duplicated URLs discovered across all attachments."""
        seen: set[str] = set()
        collected: list[str] = []
        for f in self.findings:
            for u in f.urls:
                u_clean = u.strip()
                if u_clean and u_clean not in seen:
                    seen.add(u_clean)
                    collected.append(u_clean)
        return collected

    def get_all_domains(self) -> list[str]:
        """Collect all de-duplicated domains discovered across all attachments."""
        seen: set[str] = set()
        collected: list[str] = []
        for f in self.findings:
            for d in f.domains:
                d_clean = d.strip().lower()
                if d_clean and d_clean not in seen:
                    seen.add(d_clean)
                    collected.append(d_clean)
        return collected

    def attach_url_intelligence(self, url_findings: Any) -> None:
        """
        Correlate URL findings from url_analyzer into each attachment's finding.
        Matches URLs discovered in the attachment with the corresponding finding dict.
        Records 'intelligence_lookup_completed' in the timeline once TI lookups finish.
        Incorporates the returned URL intelligence into content_risk_score and content_verdict.
        """
        findings_list = url_findings.findings if hasattr(url_findings, "findings") else (url_findings or [])
        lookup: dict[str, Any] = {}
        for uf in findings_list:
            u_key = getattr(uf, "url", None) or (uf.get("url") if isinstance(uf, dict) else None)
            if u_key:
                clean_key = _clean_and_normalize_url(u_key)
                lookup[clean_key] = uf
                lookup[u_key.strip()] = uf

        for f in self.findings:
            matched_intel: list[dict[str, Any]] = []
            for u in f.urls:
                clean_u = _clean_and_normalize_url(u)
                item = lookup.get(clean_u) or lookup.get(u.strip())
                if not item:
                    for dest in _unwrap_redirect_url(clean_u):
                        if dest in lookup:
                            item = lookup[dest]
                            break

                if item:
                    if hasattr(item, "risk_score"):
                        intel_entry = {
                            "url": item.url,
                            "domain": item.domain,
                            "risk_score": item.risk_score,
                            "reputation": item.domain_reputation,
                            "reasons": item.reasons,
                            "is_shortener": item.is_url_shortener,
                            "is_ip_url": item.is_ip_url,
                        }
                    elif isinstance(item, dict):
                        intel_entry = {
                            "url": item.get("url", clean_u),
                            "domain": item.get("domain", ""),
                            "risk_score": item.get("risk_score", 0),
                            "reputation": item.get("domain_reputation", "unknown"),
                            "reasons": item.get("reasons", []),
                            "is_shortener": item.get("is_url_shortener", False),
                            "is_ip_url": item.get("is_ip_url", False),
                        }
                    else:
                        continue

                    if not any(m["url"] == intel_entry["url"] for m in matched_intel):
                        matched_intel.append(intel_entry)

            f.url_intelligence = matched_intel

            # Incorporate URL intelligence into attachment risk score and verdict
            # Preserving NOT_ANALYZABLE for encrypted/limited/unsupported documents
            if f.content_verdict != "NOT_ANALYZABLE" and f.content_analysis_status not in ("LIMITED", "UNSUPPORTED"):
                max_url_score = max((m.get("risk_score", 0) for m in matched_intel), default=0)
                has_malicious = any(
                    m.get("reputation") == "malicious" or m.get("risk_score", 0) >= 60
                    for m in matched_intel
                )
                has_suspicious = any(
                    m.get("reputation") == "suspicious" or m.get("risk_score", 0) >= 30
                    for m in matched_intel
                )

                if has_malicious or max_url_score >= 60:
                    f.content_risk_score = min(100, max(f.content_risk_score, max_url_score))
                    f.content_verdict = "HIGH_RISK"
                    f.reasons = [r for r in f.reasons if not r.startswith("No active ") and not r.startswith("No suspicious ")]
                    mal_urls = [m["url"] for m in matched_intel if m.get("reputation") == "malicious" or m.get("risk_score", 0) >= 60]
                    f.reasons.append(f"Attachment encapsulates high-risk/malicious URL: {', '.join(mal_urls[:2])}.")
                    f.suspicious_indicators.append(f"Threat intelligence flagged embedded URL as malicious/high-risk: {mal_urls[:2]}")

                elif has_suspicious or max_url_score >= 30:
                    f.content_risk_score = min(100, max(f.content_risk_score, max_url_score))
                    if f.content_risk_score >= 60:
                        f.content_verdict = "HIGH_RISK"
                    else:
                        f.content_verdict = "SUSPICIOUS"
                    f.reasons = [r for r in f.reasons if not r.startswith("No active ") and not r.startswith("No suspicious ")]
                    susp_urls = [m["url"] for m in matched_intel if m.get("reputation") == "suspicious" or m.get("risk_score", 0) >= 30]
                    f.reasons.append(f"Attachment contains suspicious embedded URL: {', '.join(susp_urls[:2])}.")
                    f.suspicious_indicators.append(f"Threat intelligence flagged embedded URL as suspicious: {susp_urls[:2]}")

                else:
                    # All URLs are benign (risk < 30, clean reputation)
                    # Do not mark an attachment malicious just because it contains a URL!
                    # If initial score was 0, it stays 0 and NO_THREATS_DETECTED.
                    pass

            # Update timeline with lookup completion & final verdict
            if f.urls:
                f.timeline.append({
                    "step": "intelligence_lookup_completed",
                    "status": "completed",
                    "timestamp_offset_ms": 25,
                    "description": f"Threat intelligence lookup completed for {len(matched_intel)} discovered link(s)",
                })
                f.timeline.append({
                    "step": "attachment_verdict_generated",
                    "status": "completed",
                    "timestamp_offset_ms": 28,
                    "description": f"Final attachment content verdict issued: {f.content_verdict} (Risk Score: {f.content_risk_score}/100)",
                })


# ── PDF Structural & Safe Parsing Layer ─────────────────────────────

def _scan_pdf_structural_indicators(content: bytes) -> dict[str, Any]:
    """
    Safe byte-level scanner for structural PDF indicators.
    Used for defense-in-depth and fallback if object tree parsing encounters anomalies.
    """
    indicators: dict[str, Any] = {
        "has_encrypt_dict": bool(re.search(rb'/Encrypt\s+(\d+\s+\d+\s+R|<<)', content)),
        "has_javascript_token": bool(re.search(rb'/(JavaScript|JS)\b', content)),
        "has_launch_action": bool(re.search(rb'/Launch\b', content)),
        "has_openaction": bool(re.search(rb'/OpenAction\b', content)),
        "has_embedded_files": bool(re.search(rb'/(EmbeddedFiles|EF)\b', content)),
        "has_acroform": bool(re.search(rb'/AcroForm\b', content)),
        "has_aa_token": bool(re.search(rb'/AA\b', content)),
        "uri_links": [],
    }

    # Extract /URI (http...) strings directly from stream if present
    for m in re.finditer(rb'/URI\s*\((https?://[^)]+)\)', content, re.IGNORECASE):
        try:
            raw_u = m.group(1).decode("utf-8", errors="ignore")
            indicators["uri_links"].append(_clean_and_normalize_url(raw_u))
        except Exception:
            pass

    return indicators


def _analyze_pdf_content(att: Attachment) -> AttachmentContentFinding:
    """
    Safely parse and inspect an unexecuted PDF attachment.
    """
    content = att.content or b""
    timeline: list[dict[str, Any]] = [
        {
            "step": "attachment_extracted",
            "status": "completed",
            "timestamp_offset_ms": 2,
            "description": f"Extracted '{att.filename}' ({len(content)} bytes) from MIME multipart payload",
        },
        {
            "step": "content_analysis_started",
            "status": "completed",
            "timestamp_offset_ms": 5,
            "description": "Initiated safe structural PDF content parsing (no execution environment)",
        }
    ]

    # Size limit check
    max_size = getattr(config, "MAX_CONTENT_INSPECTION_BYTES", 20 * 1024 * 1024)
    if len(content) > max_size:
        timeline.append({
            "step": "content_analysis_limited",
            "status": "limited",
            "timestamp_offset_ms": 8,
            "description": f"Document size ({len(content)/(1024*1024):.1f} MB) exceeds inspection limit ({max_size/(1024*1024)} MB)",
        })
        timeline.append({
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 9,
            "description": "Generated content verdict: NOT_ANALYZABLE (size threshold exceeded)",
        })
        return AttachmentContentFinding(
            filename=att.filename,
            file_type="PDF",
            content_analysis_status="LIMITED",
            content_analyzable=False,
            encrypted=False,
            reason=f"Attachment size exceeds safe content inspection limit of {max_size // (1024*1024)} MB",
            content_risk_score=20,
            content_verdict="NOT_ANALYZABLE",
            reasons=["Document size exceeds safe content inspection threshold."],
            timeline=timeline,
        )

    # Empty content check
    if not content:
        timeline.append({
            "step": "content_analysis_failed",
            "status": "failed",
            "timestamp_offset_ms": 6,
            "description": "Attachment payload contains 0 bytes",
        })
        timeline.append({
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 7,
            "description": "Generated content verdict: NOT_ANALYZABLE (empty payload)",
        })
        return AttachmentContentFinding(
            filename=att.filename,
            file_type="PDF",
            content_analysis_status="FAILED",
            content_analyzable=False,
            encrypted=False,
            reason="Attachment content is empty",
            content_risk_score=20,
            content_verdict="NOT_ANALYZABLE",
            reasons=["Attachment content is 0 bytes."],
            timeline=timeline,
        )

    # Magic byte check
    if not content.startswith(b"%PDF"):
        timeline.append({
            "step": "content_analysis_failed",
            "status": "failed",
            "timestamp_offset_ms": 6,
            "description": "Missing %PDF magic byte header — malformed or disguised file",
        })
        timeline.append({
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 7,
            "description": "Generated content verdict: SUSPICIOUS (header anomaly)",
        })
        return AttachmentContentFinding(
            filename=att.filename,
            file_type="PDF",
            content_analysis_status="FAILED",
            content_analyzable=False,
            encrypted=False,
            reason="Invalid PDF header: Missing %PDF signature",
            content_risk_score=50,
            content_verdict="SUSPICIOUS",
            reasons=["Attachment declared as PDF lacks a valid %PDF header."],
            timeline=timeline,
        )

    # Byte-level scan for defense-in-depth
    structural = _scan_pdf_structural_indicators(content)

    # ── Attempt parsing with pypdf ───────────────────────────────
    reader: Optional[Any] = None
    is_encrypted = False
    is_fallback = False

    if _PYPDF_AVAILABLE:
        try:
            stream = io.BytesIO(content)
            reader = pypdf.PdfReader(stream, strict=False)
            is_encrypted = bool(getattr(reader, "is_encrypted", False))
        except PyPdfError as pe:
            if "encrypted" in str(pe).lower() or "password" in str(pe).lower():
                is_encrypted = True
            else:
                reader = None
                is_fallback = True
        except Exception:
            reader = None
            is_fallback = True
    else:
        is_fallback = True

    # Fallback encryption detection if pypdf reader couldn't initialize
    if not is_encrypted and structural["has_encrypt_dict"]:
        is_encrypted = True

    # ── Handle Password Protected / Encrypted PDF ────────────────
    if is_encrypted:
        timeline.append({
            "step": "content_analysis_limited",
            "status": "limited",
            "timestamp_offset_ms": 10,
            "description": "Document is password protected / encrypted; password bypass was NOT attempted",
        })
        timeline.append({
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 12,
            "description": "Generated content verdict: NOT_ANALYZABLE (password protected/encrypted)",
        })
        return AttachmentContentFinding(
            filename=att.filename,
            file_type="PDF",
            content_analysis_status="LIMITED",
            content_analyzable=False,
            encrypted=True,
            reason="PDF is password protected/encrypted.",
            pages=0,
            text_extracted=False,
            text_length=0,
            text_preview="",
            urls=[],
            domains=[],
            javascript_detected=structural["has_javascript_token"],
            javascript_details=["Structural /JavaScript token detected in encrypted stream"] if structural["has_javascript_token"] else [],
            embedded_files=[],
            forms_detected=structural["has_acroform"],
            actions_detected=["/OpenAction"] if structural["has_openaction"] else [],
            metadata={},
            suspicious_indicators=["PDF is encrypted / password protected — internal document contents cannot be inspected"],
            content_risk_score=35,
            content_verdict="NOT_ANALYZABLE",
            reasons=[
                "PDF is password protected/encrypted.",
                "Content Analysis: Limited (password bypass was not attempted).",
                "Encrypted files cannot be verified safe and are marked NOT_ANALYZABLE.",
            ],
            timeline=timeline,
        )

    # ── If unencrypted, parse document components ────────────────
    annot_uris: list[str] = []
    domains_found: list[str] = []
    text_chunks: list[str] = []
    page_count = 0
    text_extracted_ok = False
    js_detected = structural["has_javascript_token"]
    js_details: list[str] = []
    embedded_files_found: list[str] = []
    forms_detected = structural["has_acroform"]
    actions_found: list[str] = []
    metadata_extracted: dict[str, Any] = {}
    suspicious_indicators: list[str] = []

    if reader is not None:
        try:
            page_count = len(reader.pages)
            max_pages = getattr(config, "MAX_PDF_PAGES_INSPECT", 50)
            pages_to_read = min(page_count, max_pages)

            for p_idx in range(pages_to_read):
                page = reader.pages[p_idx]
                # 1. Text extraction
                try:
                    p_text = page.extract_text() or ""
                    if p_text.strip():
                        text_chunks.append(p_text.strip())
                except Exception:
                    pass

                # 2. Extract Hyperlinks from Annotations
                try:
                    if "/Annots" in page:
                        annots = page["/Annots"]
                        if hasattr(annots, "get_object"):
                            annots = annots.get_object()
                        if isinstance(annots, list):
                            for annot_ref in annots:
                                annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                                if isinstance(annot, dict):
                                    action = annot.get("/A")
                                    if hasattr(action, "get_object"):
                                        action = action.get_object()
                                    if isinstance(action, dict):
                                        s_type = action.get("/S")
                                        if s_type == "/URI" and "/URI" in action:
                                            raw_uri = str(action["/URI"])
                                            annot_uris.append(raw_uri)
                                        elif s_type == "/Launch":
                                            actions_found.append("/Launch")
                                            if "/F" in action:
                                                embedded_files_found.append(str(action["/F"]))

                                    aa = annot.get("/AA")
                                    if aa:
                                        actions_found.append("/AA")
                except Exception:
                    pass

            if text_chunks:
                text_extracted_ok = True

            # 3. Document Catalog Inspection
            root = reader.trailer.get("/Root", {})
            if hasattr(root, "get_object"):
                root = root.get_object()

            if isinstance(root, dict):
                if "/OpenAction" in root and "/OpenAction" not in actions_found:
                    actions_found.append("/OpenAction")
                if "/AA" in root and "/AA" not in actions_found:
                    actions_found.append("/AA")
                if "/AcroForm" in root:
                    forms_detected = True

                names = root.get("/Names")
                if hasattr(names, "get_object"):
                    names = names.get_object()
                if isinstance(names, dict):
                    if "/JavaScript" in names:
                        js_detected = True
                        js_details.append("Document /Names dictionary contains /JavaScript registry")
                    if "/EmbeddedFiles" in names:
                        embedded_files_found.append("EmbeddedFiles catalog present")

            # Check reader.attachments
            try:
                if hasattr(reader, "attachments") and reader.attachments:
                    for att_name in reader.attachments.keys():
                        if str(att_name) not in embedded_files_found:
                            embedded_files_found.append(str(att_name))
            except Exception:
                pass

            # 4. Metadata extraction
            if reader.metadata:
                for k, v in reader.metadata.items():
                    if v:
                        clean_k = k.lstrip("/").lower()
                        metadata_extracted[clean_k] = str(v)

        except Exception as exc:
            suspicious_indicators.append(f"Heuristic notice: Partial object tree traversal issue ({exc})")

    # Fallback to structural scanner if reader was unavailable
    if reader is None:
        page_count = 1
        is_fallback = True
        for m in re.finditer(rb'\(([^()]{4,})\)', content):
            try:
                candidate = m.group(1).decode("utf-8", errors="ignore").strip()
                if any(c.isalpha() for c in candidate):
                    text_chunks.append(candidate)
            except Exception:
                pass
        if text_chunks:
            text_extracted_ok = True

    # Check structural findings
    if structural["has_javascript_token"]:
        js_detected = True
        if "Structural /JavaScript token present in PDF stream" not in js_details:
            js_details.append("Structural /JavaScript token present in PDF stream")

    if structural["has_openaction"] and "/OpenAction" not in actions_found:
        actions_found.append("/OpenAction")

    if structural["has_launch_action"] and "/Launch" not in actions_found:
        actions_found.append("/Launch")

    if structural["has_embedded_files"] and not embedded_files_found:
        embedded_files_found.append("Structural /EmbeddedFiles object present in stream")

    # Combine and extract unique URLs (annotations prioritized, line-wraps reassembled, fragments filtered)
    extracted_pdf_urls = _extract_pdf_urls(
        annot_uris=annot_uris,
        text_chunks=text_chunks,
        structural_uris=structural.get("uri_links", []),
    )

    # Normalize URLs, unwrap redirect wrappers & extract deduplicated domains
    de_dup_urls, domains_found = _process_extracted_urls(extracted_pdf_urls)

    # Keyword check in document text
    full_text = " ".join(text_chunks)
    keywords_hit: list[str] = []
    text_lower = full_text.lower()
    susp_keywords = getattr(config, "SUSPICIOUS_PDF_CONTENT_KEYWORDS", [])
    for kw in susp_keywords:
        if kw.lower() in text_lower:
            keywords_hit.append(kw)

    # ── Heuristic Risk Scoring & Explanations ─────────────────────
    # Note: These weights represent rule-based heuristic indicators [0-100],
    # not statistical probabilities.
    content_score = 0
    reasons: list[str] = []

    if js_detected:
        content_score += 45
        suspicious_indicators.append("Heuristic signal: JavaScript code or /JS script token present in PDF")
        reasons.append("Embedded JavaScript detected inside PDF — commonly leveraged in client exploit vectors.")

    if "/Launch" in actions_found:
        content_score += 40
        suspicious_indicators.append("Heuristic signal: /Launch action configured to invoke external application")
        reasons.append("Document contains /Launch action configured to trigger external application execution.")

    if "/OpenAction" in actions_found:
        content_score += 20
        suspicious_indicators.append("Heuristic signal: Automatic /OpenAction trigger executes upon document viewing")
        reasons.append("Document contains /OpenAction trigger (observed in automated forms and exploit delivery).")

    if embedded_files_found:
        content_score += 35
        suspicious_indicators.append(f"Heuristic signal: Embedded internal file payload(s) found: {embedded_files_found}")
        reasons.append(f"Embedded internal file(s) detected ({len(embedded_files_found)} payload(s)).")

    if keywords_hit:
        base_kw_score = 30
        additional_kw_score = min(30, (len(keywords_hit) - 1) * 10)
        content_score += base_kw_score + additional_kw_score
        suspicious_indicators.append(f"Phishing/social engineering lures detected in document text ({len(keywords_hit)} keyword(s)): {keywords_hit[:5]}")
        reasons.append(f"Document text contains urgency/credential harvesting lures: {', '.join(keywords_hit[:3])}.")

    if forms_detected and (keywords_hit or de_dup_urls):
        content_score += 15
        suspicious_indicators.append("Interactive AcroForm input fields present in combination with external links/lures")
        reasons.append("Document contains interactive form fields alongside credential-harvesting indicators.")

    if de_dup_urls:
        reasons.append(f"Document contains {len(de_dup_urls)} embedded URL/hyperlink(s).")

    if is_fallback:
        suspicious_indicators.append("Primary PDF object parser failed or was unavailable; performed heuristic byte-level fallback scan.")
        reasons.append("Primary PDF parser unavailable; performed heuristic fallback scan (inspection may be partial).")

    # Final verdict determination (avoiding the over-promising "SAFE" label)
    final_score = min(content_score, 100)
    if final_score >= 60:
        verdict = "HIGH_RISK"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NO_THREATS_DETECTED"
        reasons.append("No active script payloads, embedded files, or anomalous triggers detected by this analyzer.")

    # Timeline sequence:
    # 1. content_analysis_completed
    # 2. iocs_extracted
    # 3. intelligence_lookup_requested (PENDING, only if links exist)
    # 4. attachment_verdict_generated (initial content verdict)
    analysis_status = "FALLBACK_SCAN" if is_fallback else "ANALYZED"
    timeline.append({
        "step": "content_analysis_completed",
        "status": "completed",
        "timestamp_offset_ms": 15,
        "description": f"Parsed {page_count} page(s); extracted {len(full_text)} characters of text and inspected catalog objects",
    })

    if de_dup_urls:
        timeline.append({
            "step": "iocs_extracted",
            "status": "completed",
            "timestamp_offset_ms": 16,
            "description": f"Discovered {len(de_dup_urls)} URL(s) and {len(domains_found)} parent domain(s) inside document",
        })
        timeline.append({
            "step": "intelligence_lookup_requested",
            "status": "pending",
            "timestamp_offset_ms": 18,
            "description": f"Dispatched {len(de_dup_urls)} discovered link(s) to threat intelligence pipeline for reputation lookup",
        })
    else:
        timeline.append({
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 20,
            "description": f"Issued content verdict: {verdict} (Risk Score: {final_score}/100)",
        })

    preview_len = getattr(config, "MAX_EXTRACTED_TEXT_PREVIEW_CHARS", 500)
    preview = full_text[:preview_len].strip()
    if len(full_text) > preview_len:
        preview += "..."

    return AttachmentContentFinding(
        filename=att.filename,
        file_type="PDF",
        content_analysis_status=analysis_status,
        content_analyzable=True,
        encrypted=False,
        reason=None,
        pages=page_count,
        text_extracted=text_extracted_ok,
        text_length=len(full_text),
        text_preview=preview,
        urls=de_dup_urls,
        domains=domains_found,
        javascript_detected=js_detected,
        javascript_details=js_details,
        embedded_files=embedded_files_found,
        forms_detected=forms_detected,
        actions_detected=actions_found,
        metadata=metadata_extracted,
        suspicious_indicators=suspicious_indicators,
        content_risk_score=final_score,
        content_verdict=verdict,
        reasons=reasons,
        extracted_iocs={"urls": de_dup_urls, "domains": domains_found},
        timeline=timeline,
    )


# ── Office OOXML Inspector (DOCX / XLSX / PPTX) ─────────────────────

def _analyze_ooxml_content(att: Attachment) -> AttachmentContentFinding:
    """
    Safely inspect Microsoft Office Open XML documents (DOCX, XLSX, PPTX, etc.).
    Extracts XML text, external hyperlink relationships, embedded OLE objects, and VBA macros.
    """
    content = att.content or b""
    ext = (att.extension or "").lower()

    timeline = [
        {
            "step": "attachment_extracted",
            "status": "completed",
            "timestamp_offset_ms": 2,
            "description": f"Extracted '{att.filename}' ({len(content)} bytes) from MIME multipart payload",
        },
        {
            "step": "content_analysis_started",
            "status": "completed",
            "timestamp_offset_ms": 5,
            "description": f"Initiated safe Office OOXML structural inspection ({ext})",
        }
    ]

    # Check for OLE2 encryption / EncryptedPackage
    if content.startswith(b"\xd0\xcf\x11\xe0") or b"EncryptedPackage" in content[:4096]:
        timeline.append({
            "step": "content_analysis_limited",
            "status": "limited",
            "timestamp_offset_ms": 8,
            "description": "Office document is password protected / encrypted (EncryptedPackage format)",
        })
        timeline.append({
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 10,
            "description": "Generated content verdict: NOT_ANALYZABLE (encrypted)",
        })
        return AttachmentContentFinding(
            filename=att.filename,
            file_type="OFFICE",
            content_analysis_status="LIMITED",
            content_analyzable=False,
            encrypted=True,
            reason="Office document is password protected/encrypted.",
            content_risk_score=35,
            content_verdict="NOT_ANALYZABLE",
            reasons=["Office document is password protected/encrypted — contents cannot be inspected."],
            suspicious_indicators=["Password protected Office document obscures internal contents"],
            timeline=timeline,
        )

    # Inspect OOXML ZIP package
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
        names = zf.namelist()
    except Exception as exc:
        timeline.append({
            "step": "content_analysis_failed",
            "status": "failed",
            "timestamp_offset_ms": 7,
            "description": f"Malformed Office document container: {exc}",
        })
        return AttachmentContentFinding(
            filename=att.filename,
            file_type="OFFICE",
            content_analysis_status="FAILED",
            content_analyzable=False,
            encrypted=False,
            reason=f"Malformed Office document package: {exc}",
            content_risk_score=30,
            content_verdict="UNKNOWN",
            reasons=[f"Office document package could not be read: {exc}"],
            timeline=timeline,
        )

    urls_found: list[str] = []
    domains_found: list[str] = []
    text_chunks: list[str] = []
    embedded_files: list[str] = []
    actions_found: list[str] = []
    suspicious_indicators: list[str] = []
    reasons: list[str] = []
    metadata: dict[str, Any] = {}
    is_macro = False
    score = 0

    # 1. Macro Detection (vbaProject.bin)
    for n in names:
        if "vbaProject.bin" in n or n.endswith(".vba") or "macros/" in n:
            is_macro = True
            actions_found.append("VBA_MACRO_STREAM")
            suspicious_indicators.append(f"VBA macro container detected in Office document: {n}")
            reasons.append("Document encapsulates an embedded VBA macro container (vbaProject.bin).")
            score += 40

        if "embeddings/" in n:
            embedded_files.append(n.split("/")[-1])

    if embedded_files:
        score += 30
        suspicious_indicators.append(f"Embedded OLE objects detected: {embedded_files}")
        reasons.append(f"Office document contains embedded OLE objects ({len(embedded_files)} item(s)).")

    # 2. Extract External Hyperlinks from _rels/*.rels
    for n in names:
        if n.endswith(".rels"):
            try:
                rels_xml = zf.read(n).decode("utf-8", errors="ignore")
                root = ET.fromstring(rels_xml)
                for elem in root:
                    target = elem.attrib.get("Target", "")
                    if target.startswith("http://") or target.startswith("https://"):
                        clean_u = _clean_and_normalize_url(target)
                        if clean_u and clean_u not in urls_found:
                            urls_found.append(clean_u)
            except Exception:
                pass

    # 3. Extract Document Text from primary document streams
    content_xml_files = [
        "word/document.xml",
        "xl/sharedStrings.xml",
    ] + [n for n in names if n.startswith("ppt/slides/slide") and n.endswith(".xml")]

    for xml_path in content_xml_files:
        if xml_path in names:
            try:
                raw_xml = zf.read(xml_path).decode("utf-8", errors="ignore")
                root = ET.fromstring(raw_xml)
                doc_text = "".join(root.itertext()).strip()
                if doc_text:
                    text_chunks.append(doc_text)
            except Exception:
                pass

    full_text = " ".join(text_chunks)

    # Also scan text for raw regex URLs
    for m in _DOC_URL_REGEX.finditer(full_text):
        u_str = _clean_and_normalize_url(m.group(0))
        if u_str and u_str not in urls_found:
            urls_found.append(u_str)

    # Normalize URLs, unwrap redirect wrappers & extract deduplicated domains
    urls_found, domains_found = _process_extracted_urls(urls_found)

    # 4. Keyword check
    keywords_hit: list[str] = []
    text_lower = full_text.lower()
    for kw in getattr(config, "SUSPICIOUS_PDF_CONTENT_KEYWORDS", []):
        if kw.lower() in text_lower:
            keywords_hit.append(kw)

    if keywords_hit:
        base_kw_score = 30
        additional_kw_score = min(30, (len(keywords_hit) - 1) * 10)
        score += base_kw_score + additional_kw_score
        suspicious_indicators.append(f"Social engineering/phishing wording detected in Office text ({len(keywords_hit)} keyword(s)): {keywords_hit[:4]}")
        reasons.append(f"Document text contains urgency/credential lures: {', '.join(keywords_hit[:3])}.")

    if urls_found:
        reasons.append(f"Office document contains {len(urls_found)} embedded external URL(s).")

    # 5. Metadata extraction from docProps/core.xml
    if "docProps/core.xml" in names:
        try:
            core_xml = zf.read("docProps/core.xml").decode("utf-8", errors="ignore")
            root = ET.fromstring(core_xml)
            for child in root:
                tag = child.tag.split("}")[-1].lower()
                if child.text:
                    metadata[tag] = child.text.strip()
        except Exception:
            pass

    final_score = min(score, 100)
    if final_score >= 60:
        verdict = "HIGH_RISK"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NO_THREATS_DETECTED"
        reasons.append("No active macro streams, embedded objects, or phishing lures detected in Office package.")

    timeline.append({
        "step": "content_analysis_completed",
        "status": "completed",
        "timestamp_offset_ms": 12,
        "description": f"Inspected Office container ({len(names)} parts); extracted {len(full_text)} characters and cataloged relationships",
    })

    if urls_found:
        timeline.append({
            "step": "iocs_extracted",
            "status": "completed",
            "timestamp_offset_ms": 14,
            "description": f"Discovered {len(urls_found)} URL(s) and {len(domains_found)} parent domain(s) inside Office document",
        })
        timeline.append({
            "step": "intelligence_lookup_requested",
            "status": "pending",
            "timestamp_offset_ms": 16,
            "description": f"Dispatched {len(urls_found)} discovered link(s) to threat intelligence pipeline",
        })
    else:
        timeline.append({
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 18,
            "description": f"Issued content verdict: {verdict} (Risk Score: {final_score}/100)",
        })

    preview_len = getattr(config, "MAX_EXTRACTED_TEXT_PREVIEW_CHARS", 500)
    preview = full_text[:preview_len].strip()
    if len(full_text) > preview_len:
        preview += "..."

    return AttachmentContentFinding(
        filename=att.filename,
        file_type="OFFICE",
        content_analysis_status="ANALYZED",
        content_analyzable=True,
        encrypted=False,
        pages=1,
        text_extracted=bool(full_text.strip()),
        text_length=len(full_text),
        text_preview=preview,
        urls=urls_found,
        domains=domains_found,
        javascript_detected=False,
        javascript_details=[],
        embedded_files=embedded_files,
        forms_detected=False,
        actions_detected=actions_found,
        metadata=metadata,
        suspicious_indicators=suspicious_indicators,
        content_risk_score=final_score,
        content_verdict=verdict,
        reasons=reasons,
        extracted_iocs={"urls": urls_found, "domains": domains_found},
        timeline=timeline,
    )


# ── Plain Text / HTML / CSV Handler ─────────────────────────────────

def _analyze_text_content(att: Attachment) -> AttachmentContentFinding:
    """Safely inspect plain text, CSV, or HTML attachment content."""
    content = att.content or b""
    timeline = [
        {
            "step": "attachment_extracted",
            "status": "completed",
            "timestamp_offset_ms": 2,
            "description": f"Extracted '{att.filename}' ({len(content)} bytes) from MIME multipart payload",
        },
        {
            "step": "content_analysis_started",
            "status": "completed",
            "timestamp_offset_ms": 4,
            "description": "Initiated safe text document content inspection",
        }
    ]

    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        text = content.decode("latin-1", errors="replace")

    raw_urls: list[str] = [m.group(0) for m in _DOC_URL_REGEX.finditer(text)]
    urls, domains = _process_extracted_urls(raw_urls)

    susp_indicators: list[str] = []
    reasons: list[str] = []
    score = 0

    keywords_hit: list[str] = []
    text_lower = text.lower()
    for kw in getattr(config, "SUSPICIOUS_PDF_CONTENT_KEYWORDS", []):
        if kw.lower() in text_lower:
            keywords_hit.append(kw)

    if keywords_hit:
        # Base score of 30 ensures any meaningful keyword detection achieves the SUSPICIOUS threshold (>= 30)
        # Multiple keywords scale progressively (+10 per additional keyword up to +30 max)
        # 1-3 keywords -> 30-50 (SUSPICIOUS)
        # 4+ keywords -> 60+ (HIGH_RISK) preserving the distinction between suspicious and high-risk content
        base_kw_score = 30
        additional_kw_score = min(30, (len(keywords_hit) - 1) * 10)
        score += base_kw_score + additional_kw_score
        susp_indicators.append(
            f"Phishing/social engineering lures detected in text content ({len(keywords_hit)} keyword(s)): {keywords_hit[:5]}"
        )
        reasons.append(
            f"Text document contains urgency/credential harvesting lures: {', '.join(keywords_hit[:3])}."
        )

    if urls:
        reasons.append(f"Contains {len(urls)} link(s).")

    final_score = min(score, 100)
    if final_score >= 60:
        verdict = "HIGH_RISK"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NO_THREATS_DETECTED"
        reasons.append("No active threats or suspicious indicators detected in text content.")

    timeline.append({
        "step": "content_analysis_completed",
        "status": "completed",
        "timestamp_offset_ms": 7,
        "description": f"Inspected text stream ({len(text)} characters)",
    })

    if urls:
        timeline.append({
            "step": "iocs_extracted",
            "status": "completed",
            "timestamp_offset_ms": 8,
            "description": f"Extracted {len(urls)} URL(s)",
        })
        timeline.append({
            "step": "intelligence_lookup_requested",
            "status": "pending",
            "timestamp_offset_ms": 10,
            "description": f"Dispatched {len(urls)} discovered link(s) to threat intelligence pipeline",
        })
    else:
        timeline.append({
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 11,
            "description": f"Issued content verdict: {verdict} (Risk Score: {final_score}/100)",
        })

    return AttachmentContentFinding(
        filename=att.filename,
        file_type="PLAIN_TEXT",
        content_analysis_status="ANALYZED",
        content_analyzable=True,
        encrypted=False,
        pages=1,
        text_extracted=bool(text.strip()),
        text_length=len(text),
        text_preview=text[:400].strip(),
        urls=urls,
        domains=domains,
        suspicious_indicators=susp_indicators,
        content_risk_score=final_score,
        content_verdict=verdict,
        reasons=reasons or ["No active threats or suspicious indicators detected in text content."],
        extracted_iocs={"urls": urls, "domains": domains},
        timeline=timeline,
    )


# ── Archive Inspector (With Recursive Document Inspection) ─────────

def _analyze_archive_content(att: Attachment, recursion_depth: int = 0) -> AttachmentContentFinding:
    """
    Safely inspect archive files (e.g. ZIP).
    Reads the central directory table and recursively analyzes contained documents
    (PDF, DOCX, XLSX, TXT) in memory without writing to host disk.
    """
    content = att.content or b""
    timeline = [
        {
            "step": "attachment_extracted",
            "status": "completed",
            "timestamp_offset_ms": 2,
            "description": f"Extracted '{att.filename}' ({len(content)} bytes) from MIME multipart payload",
        },
        {
            "step": "content_analysis_started",
            "status": "completed",
            "timestamp_offset_ms": 4,
            "description": "Inspecting archive directory and enclosed document contents (in-memory parsing)",
        }
    ]

    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
        names = zf.namelist()
        nested_dangerous: list[str] = []
        is_encrypted = False

        for info in zf.infolist():
            if info.flag_bits & 0x1:  # ZIP encryption flag
                is_encrypted = True
            ext = ("." + info.filename.rsplit(".", 1)[-1].lower()) if "." in info.filename else ""
            if ext in config.DANGEROUS_EXTENSIONS:
                nested_dangerous.append(info.filename)

        if is_encrypted:
            timeline.append({
                "step": "content_analysis_limited",
                "status": "limited",
                "timestamp_offset_ms": 6,
                "description": "Archive table of contents or files are password protected/encrypted",
            })
            timeline.append({
                "step": "attachment_verdict_generated",
                "status": "completed",
                "timestamp_offset_ms": 8,
                "description": "Generated content verdict: NOT_ANALYZABLE (encrypted archive)",
            })
            return AttachmentContentFinding(
                filename=att.filename,
                file_type="ARCHIVE",
                content_analysis_status="LIMITED",
                content_analyzable=False,
                encrypted=True,
                reason="Archive is password protected/encrypted.",
                content_risk_score=35,
                content_verdict="NOT_ANALYZABLE",
                reasons=["Archive is password protected/encrypted — internal contents cannot be inspected."],
                suspicious_indicators=["Password protected archive obscures potential payload"],
                timeline=timeline,
            )

        score = 0
        indicators: list[str] = []
        reasons: list[str] = []
        discovered_urls: list[str] = []
        discovered_domains: list[str] = []
        actions_found: list[str] = []
        js_detected = False

        if nested_dangerous:
            score += 50
            indicators.append(f"Archive contains executable or script payload(s): {nested_dangerous}")
            reasons.append(f"Archive encloses dangerous executable/script files: {', '.join(nested_dangerous[:3])}.")

        # ── Recursive Inspection of Enclosed Documents (Max 3 files, max 5MB each) ──
        if recursion_depth == 0:
            doc_exts = {".pdf", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".txt", ".csv", ".html"}
            analyzed_nested_count = 0

            for info in zf.infolist():
                if analyzed_nested_count >= 3:
                    break
                nested_ext = ("." + info.filename.rsplit(".", 1)[-1].lower()) if "." in info.filename else ""
                if nested_ext in doc_exts and info.file_size <= 5 * 1024 * 1024:
                    try:
                        nested_bytes = zf.read(info.filename)
                        nested_att = Attachment(
                            filename=info.filename,
                            content_type="application/pdf" if nested_ext == ".pdf" else "application/octet-stream",
                            size_bytes=len(nested_bytes),
                            extension=nested_ext,
                            content=nested_bytes,
                        )
                        nested_res = analyze_single_attachment_content(nested_att, recursion_depth=1)
                        analyzed_nested_count += 1

                        for u in nested_res.urls:
                            if u not in discovered_urls:
                                discovered_urls.append(u)
                        for d in nested_res.domains:
                            if d not in discovered_domains:
                                discovered_domains.append(d)

                        if nested_res.javascript_detected:
                            js_detected = True
                        for a in nested_res.actions_detected:
                            if a not in actions_found:
                                actions_found.append(a)

                        if nested_res.content_risk_score > score:
                            score = nested_res.content_risk_score

                        for ind in nested_res.suspicious_indicators:
                            indicators.append(f"In '{info.filename}': {ind}")

                        if nested_res.urls:
                            reasons.append(f"Nested document '{info.filename}' contains {len(nested_res.urls)} link(s).")
                    except Exception:
                        pass

        verdict = "HIGH_RISK" if score >= 50 else "SUSPICIOUS" if score >= 25 else "NO_THREATS_DETECTED"

        timeline.append({
            "step": "content_analysis_completed",
            "status": "completed",
            "timestamp_offset_ms": 8,
            "description": f"Cataloged {len(names)} archived item(s); performed in-memory inspection",
        })

        if discovered_urls:
            timeline.append({
                "step": "iocs_extracted",
                "status": "completed",
                "timestamp_offset_ms": 10,
                "description": f"Extracted {len(discovered_urls)} URL(s) from documents inside archive",
            })
            timeline.append({
                "step": "intelligence_lookup_requested",
                "status": "pending",
                "timestamp_offset_ms": 12,
                "description": f"Dispatched {len(discovered_urls)} link(s) to threat intelligence pipeline",
            })
        else:
            timeline.append({
                "step": "attachment_verdict_generated",
                "status": "completed",
                "timestamp_offset_ms": 14,
                "description": f"Issued archive verdict: {verdict} (Risk Score: {score}/100)",
            })

        return AttachmentContentFinding(
            filename=att.filename,
            file_type="ARCHIVE",
            content_analysis_status="ANALYZED",
            content_analyzable=True,
            encrypted=False,
            urls=discovered_urls,
            domains=discovered_domains,
            javascript_detected=js_detected,
            actions_detected=actions_found,
            embedded_files=names,
            suspicious_indicators=indicators,
            content_risk_score=score,
            content_verdict=verdict,
            reasons=reasons or [f"Archive contains {len(names)} files with no active threats detected."],
            extracted_iocs={"urls": discovered_urls, "domains": discovered_domains},
            timeline=timeline,
        )

    except Exception as exc:
        timeline.append({
            "step": "content_analysis_failed",
            "status": "failed",
            "timestamp_offset_ms": 6,
            "description": f"Failed to parse archive directory: {exc}",
        })
        timeline.append({
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 8,
            "description": "Issued archive verdict: UNKNOWN (parse error)",
        })
        return AttachmentContentFinding(
            filename=att.filename,
            file_type="ARCHIVE",
            content_analysis_status="FAILED",
            content_analyzable=False,
            encrypted=False,
            reason=f"Malformed archive: {exc}",
            content_risk_score=25,
            content_verdict="UNKNOWN",
            reasons=[f"Archive catalog could not be parsed: {exc}"],
            timeline=timeline,
        )


# ── Unsupported Handler ─────────────────────────────────────────────

def _unsupported_content(att: Attachment) -> AttachmentContentFinding:
    """Return structured record for formats not currently supported for deep parsing."""
    timeline = [
        {
            "step": "attachment_extracted",
            "status": "completed",
            "timestamp_offset_ms": 2,
            "description": f"Extracted '{att.filename}' from MIME multipart payload",
        },
        {
            "step": "content_analysis_completed",
            "status": "unsupported",
            "timestamp_offset_ms": 4,
            "description": f"Deep content parser for extension '{att.extension}' is not configured; static analysis applied",
        },
        {
            "step": "attachment_verdict_generated",
            "status": "completed",
            "timestamp_offset_ms": 5,
            "description": "Issued verdict: NOT_ANALYZABLE (unsupported format)",
        }
    ]

    return AttachmentContentFinding(
        filename=att.filename,
        file_type="UNKNOWN",
        content_analysis_status="UNSUPPORTED",
        content_analyzable=False,
        encrypted=False,
        reason=f"Deep document content parser is not configured for file type '{att.extension or 'unknown'}'.",
        content_risk_score=0,
        content_verdict="NOT_ANALYZABLE",
        reasons=[f"File type '{att.extension or 'unknown'}' evaluated via static properties only."],
        timeline=timeline,
    )


# ── Public API ──────────────────────────────────────────────────────

def analyze_single_attachment_content(
    att: Attachment,
    recursion_depth: int = 0,
) -> AttachmentContentFinding:
    """
    Safely inspect the internal content of a single email attachment.
    Never throws an unhandled exception.
    """
    ext = (att.extension or "").lower()
    ct = (att.content_type or "").lower()
    content = att.content or b""

    # Detect PDF
    if ext == ".pdf" or ct == "application/pdf" or content.startswith(b"%PDF"):
        try:
            return _analyze_pdf_content(att)
        except Exception as exc:
            return AttachmentContentFinding(
                filename=att.filename,
                file_type="PDF",
                content_analysis_status="FAILED",
                content_analyzable=False,
                encrypted=False,
                reason=f"PDF parsing error: {exc}",
                content_risk_score=30,
                content_verdict="UNKNOWN",
                reasons=[f"Safe PDF parser encountered an error: {exc}"],
                timeline=[
                    {"step": "attachment_extracted", "status": "completed", "timestamp_offset_ms": 2, "description": f"Extracted '{att.filename}'"},
                    {"step": "content_analysis_failed", "status": "failed", "timestamp_offset_ms": 5, "description": f"Parser failure: {exc}"},
                    {"step": "attachment_verdict_generated", "status": "completed", "timestamp_offset_ms": 6, "description": "Verdict: UNKNOWN (parse failure)"},
                ]
            )

    # Detect Microsoft Office Documents (DOCX, XLSX, PPTX, DOCM, XLSM, PPTM)
    ooxml_exts = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
    if ext in ooxml_exts or "openxmlformats" in ct or "ms-word" in ct or "ms-excel" in ct:
        try:
            return _analyze_ooxml_content(att)
        except Exception as exc:
            return AttachmentContentFinding(
                filename=att.filename,
                file_type="OFFICE",
                content_analysis_status="FAILED",
                content_analyzable=False,
                encrypted=False,
                reason=f"Office document error: {exc}",
                content_risk_score=25,
                content_verdict="UNKNOWN",
                reasons=[f"Office document inspection failed: {exc}"],
            )

    # Detect Plain text / CSV / HTML
    if ext in {".txt", ".csv", ".log"} or ct.startswith("text/plain"):
        try:
            return _analyze_text_content(att)
        except Exception as exc:
            return AttachmentContentFinding(
                filename=att.filename,
                file_type="PLAIN_TEXT",
                content_analysis_status="FAILED",
                content_analyzable=False,
                encrypted=False,
                reason=f"Text decode error: {exc}",
                content_risk_score=10,
                content_verdict="UNKNOWN",
                reasons=[f"Text content could not be read: {exc}"],
            )

    # Detect ZIP Archive
    if ext == ".zip" or ct in {"application/zip", "application/x-zip-compressed"} or content.startswith(b"PK\x03\x04"):
        try:
            return _analyze_archive_content(att, recursion_depth=recursion_depth)
        except Exception as exc:
            return AttachmentContentFinding(
                filename=att.filename,
                file_type="ARCHIVE",
                content_analysis_status="FAILED",
                content_analyzable=False,
                encrypted=False,
                reason=f"Archive read error: {exc}",
                content_risk_score=20,
                content_verdict="UNKNOWN",
                reasons=[f"Archive could not be parsed: {exc}"],
            )

    # Unsupported format
    return _unsupported_content(att)


def analyze_attachment_contents(attachments: list[Attachment]) -> AttachmentContentAnalysis:
    """
    Perform deep, safe content inspection on all attachments in an email.

    Args:
        attachments: list of Attachment objects from email_parser.

    Returns:
        AttachmentContentAnalysis with per-document content findings and aggregated counters.
    """
    if not attachments:
        return AttachmentContentAnalysis(
            total_count=0,
            analyzed_count=0,
            limited_count=0,
            failed_count=0,
            findings=[],
        )

    findings: list[AttachmentContentFinding] = []
    analyzed = 0
    limited = 0
    failed = 0

    for att in attachments:
        finding = analyze_single_attachment_content(att)
        findings.append(finding)
        if finding.content_analysis_status == "ANALYZED":
            analyzed += 1
        elif finding.content_analysis_status in ("LIMITED", "FALLBACK_SCAN"):
            limited += 1
        elif finding.content_analysis_status == "FAILED":
            failed += 1

    return AttachmentContentAnalysis(
        total_count=len(findings),
        analyzed_count=analyzed,
        limited_count=limited,
        failed_count=failed,
        findings=findings,
    )


def attach_url_intelligence(analysis: AttachmentContentAnalysis, url_findings: Any) -> None:
    """Module-level convenience wrapper for AttachmentContentAnalysis.attach_url_intelligence."""
    if analysis and hasattr(analysis, "attach_url_intelligence"):
        analysis.attach_url_intelligence(url_findings)

