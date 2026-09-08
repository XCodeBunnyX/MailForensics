"""
GmailGuard — Attachment Analyzer

Performs STATIC-ONLY analysis of email attachments.
Checks filename, extension, MIME type, size, and structural indicators.

CRITICAL RULES:
  - Attachments are NEVER executed.
  - No sandboxing or dynamic analysis is performed.
  - Content bytes are inspected only for magic byte/header checks.
  - Missing attachments cause no error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import config
from .email_parser import Attachment


# ── Magic byte signatures for executable detection ───────────────
# Checked against first 8 bytes of attachment content.
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ",                 "Windows PE executable (EXE/DLL)"),
    (b"\x7fELF",            "ELF binary (Linux executable)"),
    (b"\xca\xfe\xba\xbe",   "Java class file / Mach-O fat binary"),
    (b"PK\x03\x04",         "ZIP archive (may contain malicious files)"),
    (b"Rar!",               "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"%PDF",               "PDF file"),
    (b"\xd0\xcf\x11\xe0",   "OLE2 Compound Document (Office / macro-enabled)"),
    (b"\x50\x4b\x03\x04",   "OOXML (Office Open XML — may be macro-enabled)"),
    (b"#!/",                "Script file (shebang)"),
]


def _check_magic_bytes(content: bytes) -> list[str]:
    """Return list of magic-byte indicators found in file content."""
    if not content:
        return []
    header = content[:8]
    found = []
    for sig, label in _MAGIC_SIGNATURES:
        if header.startswith(sig):
            found.append(label)
    return found


def _has_double_extension(filename: str) -> bool:
    """
    Detect double-extension tricks like 'invoice.pdf.exe'.
    Returns True if the real final extension is dangerous and there
    is another extension before it.
    """
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    final_ext = "." + parts[-1]
    return final_ext in config.DANGEROUS_EXTENSIONS


def _has_suspicious_filename(filename: str) -> list[str]:
    """Return list of suspicious keywords found in filename."""
    name_lower = filename.lower()
    return [kw for kw in config.SUSPICIOUS_FILENAME_KEYWORDS if kw in name_lower]


@dataclass
class AttachmentFinding:
    """Analysis result for a single attachment."""
    filename: str
    extension: str
    content_type: str
    size_bytes: int
    size_mb: float

    # Risk flags
    is_dangerous_extension: bool
    is_archive: bool
    is_macro_enabled: bool
    has_double_extension: bool
    suspicious_filename_keywords: list[str]
    magic_byte_matches: list[str]
    size_exceeds_limit: bool
    mime_extension_mismatch: bool   # MIME type doesn't match extension

    risk_score: int      # 0-100
    reasons: list[str]


@dataclass
class AttachmentAnalysis:
    """Aggregated attachment analysis."""
    total_count: int
    suspicious_count: int
    findings: list[AttachmentFinding]


def _mime_matches_extension(content_type: str, extension: str) -> bool:
    """Basic check: does the MIME type roughly match the extension?"""
    ext = extension.lower()
    ct = content_type.lower()

    _EXPECTED: dict[str, list[str]] = {
        ".pdf":  ["application/pdf"],
        ".docx": ["application/vnd.openxmlformats", "application/zip"],
        ".xlsx": ["application/vnd.openxmlformats", "application/zip"],
        ".doc":  ["application/msword", "application/vnd.ms-"],
        ".xls":  ["application/vnd.ms-excel"],
        ".zip":  ["application/zip", "application/x-zip"],
        ".exe":  ["application/x-msdownload", "application/x-executable",
                  "application/octet-stream"],
        ".txt":  ["text/plain"],
        ".html": ["text/html"],
        ".png":  ["image/png"],
        ".jpg":  ["image/jpeg"],
        ".gif":  ["image/gif"],
    }

    expected_types = _EXPECTED.get(ext, [])
    if not expected_types:
        return True   # unknown extension → assume no mismatch

    return any(ct.startswith(t) for t in expected_types)


def _analyze_single_attachment(att: Attachment) -> AttachmentFinding:
    """Analyze one attachment and compute a risk score."""
    reasons: list[str] = []
    score = 0
    size_mb = att.size_bytes / (1024 * 1024)

    # Extension checks
    is_dangerous = att.extension in config.DANGEROUS_EXTENSIONS
    if is_dangerous:
        score += 40
        reasons.append(
            f"File extension '{att.extension}' is inherently dangerous "
            "(executable, script, or macro-enabled document)."
        )

    is_archive = att.extension in config.ARCHIVE_EXTENSIONS
    if is_archive:
        score += 15
        reasons.append(
            f"Archive file '{att.extension}' — may contain embedded malicious files. "
            "Contents cannot be analyzed without extraction."
        )

    is_macro = att.extension in config.MACRO_INDICATOR_EXTENSIONS
    if is_macro and not is_dangerous:
        score += 30
        reasons.append(
            f"Macro-enabled Office document ('{att.extension}') — "
            "macros can execute arbitrary code if enabled."
        )

    # Double extension
    double_ext = _has_double_extension(att.filename)
    if double_ext:
        score += 25
        reasons.append(
            f"Double extension detected in '{att.filename}' — "
            "common technique to disguise executable files."
        )

    # Suspicious filename keywords
    susp_keywords = _has_suspicious_filename(att.filename)
    if susp_keywords:
        score += 10
        reasons.append(
            f"Filename contains social-engineering keywords: {susp_keywords}."
        )

    # Magic byte analysis
    magic = _check_magic_bytes(att.content or b"")
    if magic and not is_dangerous:
        score += 20
        reasons.append(f"File header (magic bytes) indicates: {magic}.")

    # Size check
    size_over = size_mb > config.MAX_SAFE_ATTACHMENT_SIZE_MB
    if size_over:
        score += 5
        reasons.append(
            f"Attachment size ({size_mb:.1f} MB) exceeds "
            f"threshold of {config.MAX_SAFE_ATTACHMENT_SIZE_MB} MB."
        )

    # MIME type vs extension mismatch
    matches = _mime_matches_extension(att.content_type, att.extension)
    mime_mismatch = not matches and att.extension != ""
    if mime_mismatch:
        score += 15
        reasons.append(
            f"MIME type '{att.content_type}' does not match "
            f"file extension '{att.extension}' — possible disguised file."
        )

    return AttachmentFinding(
        filename=att.filename,
        extension=att.extension,
        content_type=att.content_type,
        size_bytes=att.size_bytes,
        size_mb=round(size_mb, 2),
        is_dangerous_extension=is_dangerous,
        is_archive=is_archive,
        is_macro_enabled=is_macro,
        has_double_extension=double_ext,
        suspicious_filename_keywords=susp_keywords,
        magic_byte_matches=magic,
        size_exceeds_limit=size_over,
        mime_extension_mismatch=mime_mismatch,
        risk_score=min(score, 100),
        reasons=reasons,
    )


def analyze_attachments(attachments: list[Attachment]) -> AttachmentAnalysis:
    """
    Statically analyze all email attachments.

    Args:
        attachments: List of Attachment objects from email_parser.

    Returns:
        AttachmentAnalysis with per-file findings and aggregate stats.
        If no attachments, returns a zero-count clean result.
    """
    if not attachments:
        return AttachmentAnalysis(total_count=0, suspicious_count=0, findings=[])

    findings: list[AttachmentFinding] = []
    for att in attachments:
        findings.append(_analyze_single_attachment(att))

    findings.sort(key=lambda f: f.risk_score, reverse=True)
    suspicious_count = sum(1 for f in findings if f.risk_score >= 30)

    return AttachmentAnalysis(
        total_count=len(findings),
        suspicious_count=suspicious_count,
        findings=findings,
    )
