"""Unit tests for attachment_analyzer.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from ..email_parser import Attachment
from ..attachment_analyzer import analyze_attachments


def _make_att(filename: str, content_type: str = "application/octet-stream",
              content: bytes = b"") -> Attachment:
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    return Attachment(
        filename=filename,
        content_type=content_type,
        size_bytes=len(content),
        extension=ext,
        content=content,
    )


class TestAttachmentAnalyzer:
    def test_no_attachments_returns_zero(self):
        result = analyze_attachments([])
        assert result.total_count == 0
        assert result.suspicious_count == 0
        assert result.findings == []

    def test_exe_attachment_flagged(self):
        att = _make_att("malware.exe", "application/x-msdownload")
        result = analyze_attachments([att])
        assert result.suspicious_count == 1
        assert result.findings[0].is_dangerous_extension is True

    def test_pdf_not_flagged(self):
        att = _make_att("invoice.pdf", "application/pdf")
        result = analyze_attachments([att])
        assert result.findings[0].is_dangerous_extension is False

    def test_double_extension_detected(self):
        att = _make_att("document.pdf.exe")
        result = analyze_attachments([att])
        assert result.findings[0].has_double_extension is True

    def test_macro_enabled_docm_flagged(self):
        att = _make_att("report.docm",
                        "application/vnd.ms-word.document.macroEnabled.12")
        result = analyze_attachments([att])
        assert result.findings[0].is_macro_enabled is True

    def test_archive_detected(self):
        att = _make_att("payload.zip", "application/zip", b"PK\x03\x04")
        result = analyze_attachments([att])
        assert result.findings[0].is_archive is True

    def test_suspicious_filename_keyword(self):
        att = _make_att("urgent_invoice_payment.pdf", "application/pdf")
        result = analyze_attachments([att])
        assert len(result.findings[0].suspicious_filename_keywords) > 0

    def test_magic_bytes_exe_detected(self):
        # MZ header = Windows PE
        att = _make_att("disguised.pdf", "application/pdf",
                        content=b"MZ\x90\x00" + b"\x00" * 100)
        result = analyze_attachments([att])
        assert len(result.findings[0].magic_byte_matches) > 0

    def test_never_executes(self):
        # Providing a real executable magic byte — must not crash or execute
        att = _make_att("test.exe", content=b"MZ" + b"\xff" * 200)
        result = analyze_attachments([att])   # should complete without error
        assert result.total_count == 1

    def test_multiple_attachments(self):
        atts = [
            _make_att("clean.pdf", "application/pdf"),
            _make_att("bad.exe", "application/x-msdownload"),
        ]
        result = analyze_attachments(atts)
        assert result.total_count == 2
        # exe should have higher risk score than pdf
        scores = {f.filename: f.risk_score for f in result.findings}
        assert scores["bad.exe"] > scores["clean.pdf"]
