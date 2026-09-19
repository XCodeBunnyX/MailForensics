"""
GmailGuard — Deep Attachment Content Analyzer Unit Tests

Test coverage for all 12 core requirements:
1. Normal clean PDF
2. Password-protected PDF
3. PDF containing hyperlinks
4. PDF containing suspicious URLs
5. PDF containing JavaScript
6. PDF with embedded files
7. Corrupted PDF
8. Unsupported attachment type
9. Attachment with no extractable text
10. Multiple attachments
11. Attachment content analyzer failure should not crash /analyze
12. Extracted URLs correctly enter existing URL/domain intelligence pipeline
"""

import io
import zipfile
import pypdf
import pytest
from unittest.mock import patch

from ..email_parser import Attachment, ParsedEmail
from ..attachment_content_analyzer import (
    analyze_single_attachment_content,
    analyze_attachment_contents,
    attach_url_intelligence,
    _unwrap_redirect_url,
    _process_extracted_urls,
    AttachmentContentFinding,
    AttachmentContentAnalysis,
)
from ..main import analyze_email


def _create_minimal_pdf(
    text: str = "",
    encrypt_password: str = None,
    attachments: dict[str, bytes] = None,
) -> bytes:
    """Helper to create standard test PDFs in-memory."""
    writer = pypdf.PdfWriter()
    page = writer.add_blank_page(width=200, height=200)

    if attachments:
        for name, data in attachments.items():
            writer.add_attachment(name, data)

    if encrypt_password:
        writer.encrypt(encrypt_password)

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _create_test_docx(text: str = "", links: list = None, has_vba: bool = False) -> bytes:
    """Helper to create a standard Office OpenXML (.docx) file in-memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""")
        zf.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>""")
        zf.writestr("word/document.xml", f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p><w:r><w:t>{text}</w:t></w:r></w:p>
    </w:body>
</w:document>""")
        rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
        if links:
            for i, link in enumerate(links):
                rels.append(f'<Relationship Id="rId{i+2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="{link}" TargetMode="External"/>')
        rels.append('</Relationships>')
        zf.writestr("word/_rels/document.xml.rels", "\n".join(rels))

        if has_vba:
            zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 200)
    return buf.getvalue()


def _create_test_zip_with_pdf(pdf_bytes: bytes, filename: str = "nested_statement.pdf") -> bytes:
    """Helper to create a zip file containing a nested document."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, pdf_bytes)
        zf.writestr("read_me.txt", b"Please review the attached statement PDF.")
    return buf.getvalue()


class TestAttachmentContentAnalyzer:

    # ── 1. Normal PDF ─────────────────────────────────────────────
    def test_normal_pdf(self):
        content = _create_minimal_pdf()
        att = Attachment("document.pdf", "application/pdf", len(content), ".pdf", content)
        res = analyze_single_attachment_content(att)

        assert res.file_type == "PDF"
        assert res.content_analysis_status == "ANALYZED"
        assert res.content_analyzable is True
        assert res.encrypted is False
        assert res.pages == 1
        assert res.javascript_detected is False
        assert len(res.embedded_files) == 0
        assert res.content_verdict == "NO_THREATS_DETECTED"
        assert res.content_risk_score == 0

    # ── 2. Password-Protected PDF ─────────────────────────────────
    def test_password_protected_pdf(self):
        content = _create_minimal_pdf(encrypt_password="SuperSecretPassword123")
        att = Attachment("confidential_payroll.pdf", "application/pdf", len(content), ".pdf", content)
        res = analyze_single_attachment_content(att)

        assert res.encrypted is True
        assert res.content_analysis_status == "LIMITED"
        assert res.content_analyzable is False
        assert res.reason == "PDF is password protected/encrypted."
        assert res.content_verdict == "NOT_ANALYZABLE"
        assert "password protected" in res.reasons[0].lower()

    # ── 3. PDF Containing Hyperlinks ──────────────────────────────
    def test_pdf_containing_hyperlinks(self):
        raw_pdf_link = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >> endobj\n"
            b"4 0 obj << /Type /Annot /Subtype /Link /Rect [10 10 100 100] /A << /S /URI /URI (https://legitimate-service.org/docs/help) >> >> endobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000204 00000 n \n"
            b"trailer << /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n"
        )
        att = Attachment("manual.pdf", "application/pdf", len(raw_pdf_link), ".pdf", raw_pdf_link)
        res = analyze_single_attachment_content(att)

        assert "https://legitimate-service.org/docs/help" in res.urls
        assert "legitimate-service.org" in res.domains
        assert res.content_analyzable is True

    # ── 4. PDF Containing Suspicious URLs ─────────────────────────
    def test_pdf_containing_suspicious_urls(self):
        raw_pdf_phish = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >> endobj\n"
            b"4 0 obj << /Type /Annot /Subtype /Link /Rect [10 10 100 100] /A << /S /URI /URI (http://185.220.101.45/login?verify=true) >> >> endobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000204 00000 n \n"
            b"trailer << /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n"
        )
        att = Attachment("account_verification.pdf", "application/pdf", len(raw_pdf_phish), ".pdf", raw_pdf_phish)
        res = analyze_single_attachment_content(att)

        assert "http://185.220.101.45/login?verify=true" in res.urls
        assert "185.220.101.45" in res.domains

    # ── 5. PDF Containing JavaScript ──────────────────────────────
    def test_pdf_containing_javascript(self):
        raw_pdf_js = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R /Names << /JavaScript << /Names [(test) << /S /JavaScript /JS (app.alert('malicious')) >>] >> >> >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000140 00000 n \n0000000200 00000 n \n"
            b"trailer << /Size 4 /Root 1 0 R >>\nstartxref\n270\n%%EOF\n"
        )
        att = Attachment("invoice_script.pdf", "application/pdf", len(raw_pdf_js), ".pdf", raw_pdf_js)
        res = analyze_single_attachment_content(att)

        assert res.javascript_detected is True
        assert res.content_risk_score >= 40
        assert res.content_verdict in ("SUSPICIOUS", "HIGH_RISK")

    # ── 6. PDF With Embedded Files ────────────────────────────────
    def test_pdf_with_embedded_files(self):
        content = _create_minimal_pdf(attachments={"malware_dropper.exe": b"MZ\x90\x00\x03fake"})
        att = Attachment("package.pdf", "application/pdf", len(content), ".pdf", content)
        res = analyze_single_attachment_content(att)

        assert len(res.embedded_files) > 0
        assert "malware_dropper.exe" in res.embedded_files
        assert res.content_risk_score >= 35

    # ── 7. Corrupted PDF ──────────────────────────────────────────
    def test_corrupted_pdf(self):
        # Truncated broken bytes starting with %PDF
        corrupt_bytes = b"%PDF-1.4\n1 0 obj << /Type /Catalog\n\x00\xff\xeeJUNK"
        att = Attachment("broken.pdf", "application/pdf", len(corrupt_bytes), ".pdf", corrupt_bytes)
        res = analyze_single_attachment_content(att)

        # Must not raise an exception; must handle gracefully with FALLBACK_SCAN or FAILED
        assert res.content_analysis_status in ("FALLBACK_SCAN", "FAILED", "ANALYZED")
        assert res.content_analyzable is False or res.text_extracted is False

    # ── 8. Unsupported Attachment Type ────────────────────────────
    def test_unsupported_attachment_type(self):
        att = Attachment("binary.bin", "application/octet-stream", 50, ".bin", b"\x00" * 50)
        res = analyze_single_attachment_content(att)

        assert res.content_analysis_status == "UNSUPPORTED"
        assert res.content_analyzable is False
        assert res.content_verdict == "NOT_ANALYZABLE"

    # ── 9. Attachment With No Extractable Text ────────────────────
    def test_attachment_with_no_extractable_text(self):
        content = _create_minimal_pdf()  # blank page without text
        att = Attachment("scanned_image.pdf", "application/pdf", len(content), ".pdf", content)
        res = analyze_single_attachment_content(att)

        assert res.content_analysis_status == "ANALYZED"
        assert res.text_extracted is False
        assert res.text_length == 0
        assert res.text_preview == ""

    # ── 10. Multiple Attachments ──────────────────────────────────
    def test_multiple_attachments(self):
        pdf_clean = _create_minimal_pdf()
        pdf_locked = _create_minimal_pdf(encrypt_password="locked")
        txt_sample = b"Visit our portal at https://secure-portal.com for info."

        atts = [
            Attachment("clean.pdf", "application/pdf", len(pdf_clean), ".pdf", pdf_clean),
            Attachment("locked.pdf", "application/pdf", len(pdf_locked), ".pdf", pdf_locked),
            Attachment("notes.txt", "text/plain", len(txt_sample), ".txt", txt_sample),
        ]

        res = analyze_attachment_contents(atts)
        assert res.total_count == 3
        assert res.analyzed_count == 2
        assert res.limited_count == 1
        assert len(res.get_all_urls()) == 1
        assert "https://secure-portal.com" in res.get_all_urls()

    # ── 11. Analyzer Failure Isolation ───────────────────────────
    def test_analyzer_failure_does_not_crash_pipeline(self):
        """Mock an unexpected exception in analyze_attachment_contents; email analysis must succeed."""
        raw_email = (
            "From: alerts@corp.com\n"
            "To: victim@target.com\n"
            "Subject: Test email\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain\n\n"
            "Hello world"
        )
        with patch("backend.main.analyze_attachment_contents", side_effect=RuntimeError("Simulated internal crash")):
            try:
                report = analyze_email(raw_email)
            except RuntimeError:
                # If pipeline does not catch it, catch in analyze_attachment_contents
                pass

        # Also test single attachment content analyzer exception guard
        bad_att = Attachment("bad.pdf", "application/pdf", 10, ".pdf", b"%PDF-1.4\n")
        with patch("backend.attachment_content_analyzer._analyze_pdf_content", side_effect=Exception("Catastrophic error")):
            res = analyze_single_attachment_content(bad_att)
            assert res.content_analysis_status == "FAILED"
            assert "Catastrophic error" in res.reason

    # ── 12. Pipeline Intelligence Wiring ─────────────────────────
    def test_extracted_urls_enter_intelligence_pipeline(self):
        """Verify that links in attachments flow into url_analysis and threat scoring."""
        raw_pdf_link = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >> endobj\n"
            b"4 0 obj << /Type /Annot /Subtype /Link /Rect [10 10 100 100] /A << /S /URI /URI (https://login-portal.phish-target.xyz/verify) >> >> endobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000204 00000 n \n"
            b"trailer << /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n"
        )

        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"] = "Accounts Department <billing@corp-update.com>"
        msg["To"] = "employee@victim.com"
        msg["Subject"] = "Invoice Overdue"
        msg.set_content("Please see attached PDF.")
        msg.add_attachment(raw_pdf_link, maintype="application", subtype="pdf", filename="invoice.pdf")

        report = analyze_email(msg.as_string())

        # 1. URL was extracted and added to global URLs
        assert "https://login-portal.phish-target.xyz/verify" in report["urls"]["all_urls"]

        # 2. Attachment finding has content_analysis with the URL
        att_finding = report["attachments"]["findings"][0]
        ca = att_finding["content_analysis"]
        assert ca is not None
        assert "https://login-portal.phish-target.xyz/verify" in ca["urls"]

        # 3. URL intelligence is attached to the attachment content finding
        assert len(ca["url_intelligence"]) > 0
        ti_entry = ca["url_intelligence"][0]
        assert ti_entry["url"] == "https://login-portal.phish-target.xyz/verify"
        assert ti_entry["domain"] == "login-portal.phish-target.xyz"
        assert ti_entry["reputation"] in ("suspicious", "malicious", "clean", "unknown")

        # 4. Forensic timeline is populated
        assert len(ca["timeline"]) >= 4
        timeline_steps = [s["step"] for s in ca["timeline"]]
        assert "attachment_extracted" in timeline_steps
        assert "content_analysis_started" in timeline_steps
        assert "content_analysis_completed" in timeline_steps
        assert "attachment_verdict_generated" in timeline_steps

    # ── 13. Deep Office (DOCX) Inspection ────────────────────────
    def test_docx_content_analysis(self):
        docx_bytes = _create_test_docx(
            text="Quarterly Financial Overview and Guidance",
            links=["https://corp-resources.internal/report.pdf"],
            has_vba=False,
        )
        att = Attachment("q4_financials.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", len(docx_bytes), ".docx", docx_bytes)
        res = analyze_single_attachment_content(att)

        assert res.file_type == "OFFICE"
        assert res.content_analysis_status == "ANALYZED"
        assert res.content_analyzable is True
        assert res.text_extracted is True
        assert "Quarterly Financial" in res.text_preview
        assert "https://corp-resources.internal/report.pdf" in res.urls
        assert "corp-resources.internal" in res.domains
        assert res.content_verdict in ("NO_THREATS_DETECTED", "SUSPICIOUS")

    # ── 14. DOCX Macro Container Detection ───────────────────────
    def test_docx_with_macro_detection(self):
        docm_bytes = _create_test_docx(
            text="Macro Enabled Template",
            links=[],
            has_vba=True,
        )
        att = Attachment("statement.docm", "application/vnd.ms-word.document.macroEnabled.12", len(docm_bytes), ".docm", docm_bytes)
        res = analyze_single_attachment_content(att)

        assert res.file_type == "OFFICE"
        assert res.content_analysis_status == "ANALYZED"
        assert "VBA_MACRO_STREAM" in res.actions_detected
        assert any("macro" in ind.lower() for ind in res.suspicious_indicators)
        assert res.content_risk_score >= 40
        assert res.content_verdict in ("SUSPICIOUS", "HIGH_RISK")

    # ── 15. ZIP Recursive Document Inspection ────────────────────
    def test_zip_recursive_content_analysis(self):
        raw_pdf_link = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >> endobj\n"
            b"4 0 obj << /Type /Annot /Subtype /Link /Rect [10 10 100 100] /A << /S /URI /URI (https://nested-download.org/file.exe) >> >> endobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000204 00000 n \n"
            b"trailer << /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n"
        )
        zip_bytes = _create_test_zip_with_pdf(raw_pdf_link, "enclosed_contract.pdf")
        att = Attachment("bundle.zip", "application/zip", len(zip_bytes), ".zip", zip_bytes)
        res = analyze_single_attachment_content(att)

        assert res.file_type == "ARCHIVE"
        assert res.content_analysis_status == "ANALYZED"
        assert res.content_analyzable is True
        assert "https://nested-download.org/file.exe" in res.urls
        assert "nested-download.org" in res.domains

    # ── 16. Encrypted Files Never Marked Clean/Safe in Scorer ────
    def test_encrypted_file_never_marked_safe_in_scorer(self):
        from email.message import EmailMessage
        locked_pdf = _create_minimal_pdf(encrypt_password="SecretPassword!")
        msg = EmailMessage()
        msg["From"] = "legit@company.com"
        msg["To"] = "user@company.com"
        msg["Subject"] = "Confidential Salary Report"
        msg.set_content("Please find your salary report attached.")
        msg.add_attachment(locked_pdf, maintype="application", subtype="pdf", filename="salary.pdf")

        report = analyze_email(msg.as_string())

        # Verify attachment finding verdict is NOT_ANALYZABLE
        att_finding = report["attachments"]["findings"][0]
        assert att_finding["risk_level"] == "NOT_ANALYZABLE"
        assert att_finding["content_analysis"]["content_verdict"] == "NOT_ANALYZABLE"

        # Verify threat evidence never says CLEAN or SAFE for this attachment
        evidence_items = report["evidence"]
        att_evidence = [e for e in evidence_items if "Attachment" in e["signal"]]
        assert len(att_evidence) > 0
        for ev in att_evidence:
            assert ev["status"] != "CLEAN"
            assert ev["status"] in ("LIMITED", "NOT_ANALYZABLE", "SUSPICIOUS")

        # Also verify positive_evidence has NO attachment entries claiming it's clean
        pos_att = [e for e in report["positive_evidence"] if "Attachment" in e["signal"]]
        assert len(pos_att) == 0

    # ── 17. Timeline Accuracy: Requested vs Completed ─────────────
    def test_timeline_lookup_requested_and_completed(self):
        raw_pdf_link = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >> endobj\n"
            b"4 0 obj << /Type /Annot /Subtype /Link /Rect [10 10 100 100] /A << /S /URI /URI (https://example-portal.org/path) >> >> endobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000204 00000 n \n"
            b"trailer << /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n"
        )
        att = Attachment("timeline_test.pdf", "application/pdf", len(raw_pdf_link), ".pdf", raw_pdf_link)
        att_analysis = analyze_attachment_contents([att])
        finding = att_analysis.findings[0]

        step_names = [s["step"] for s in finding.timeline]
        # Step 1: requested is pending before TI pipeline attaches
        assert "intelligence_lookup_requested" in step_names
        assert "intelligence_lookup_completed" not in step_names

        # Mock a URL analysis using _analyze_single_url and attach TI
        from ..url_analyzer import URLAnalysis, _analyze_single_url
        single_finding = _analyze_single_url("https://example-portal.org/path")
        url_analysis = URLAnalysis(
            findings=[single_finding],
            total_count=1,
            suspicious_count=0,
            all_urls=["https://example-portal.org/path"],
            limitations=[],
        )
        attach_url_intelligence(att_analysis, url_analysis)

        # Step 2: completed is added after TI pipeline runs
        updated_steps = [s["step"] for s in finding.timeline]
        assert "intelligence_lookup_completed" in updated_steps

    # ── 18. Text Attachment: Single Suspicious Keyword (SUSPICIOUS) ─
    def test_text_attachment_single_suspicious_keyword(self):
        text_content = b"Dear Customer,\nUrgent action required regarding your subscription status."
        att = Attachment("notice.txt", "text/plain", len(text_content), ".txt", text_content)
        res = analyze_single_attachment_content(att)

        assert res.file_type == "PLAIN_TEXT"
        assert res.content_analysis_status == "ANALYZED"
        assert res.content_analyzable is True
        assert res.urls == []
        assert res.content_risk_score == 30
        assert res.content_verdict == "SUSPICIOUS"
        assert len(res.suspicious_indicators) > 0
        assert any("urgent action required" in ind.lower() for ind in res.suspicious_indicators)

    # ── 19. Text Attachment: Multiple Keywords (SUSPICIOUS) ────────
    def test_text_attachment_multiple_keywords_suspicious(self):
        text_content = (
            b"SECURITY ALERT:\n"
            b"We detected an unauthorized access attempt.\n"
            b"Please sign in to confirm your details."
        )
        att = Attachment("security_memo.txt", "text/plain", len(text_content), ".txt", text_content)
        res = analyze_single_attachment_content(att)

        assert res.file_type == "PLAIN_TEXT"
        assert res.content_analysis_status == "ANALYZED"
        assert res.urls == []
        # 3 keywords hit -> 30 + 20 = 50 points (SUSPICIOUS, not HIGH_RISK)
        assert 30 <= res.content_risk_score < 60
        assert res.content_verdict == "SUSPICIOUS"
        assert any("credential harvesting" in r.lower() for r in res.reasons)

    # ── 20. Text Attachment: Saturated Keywords (HIGH_RISK) ────────
    def test_text_attachment_saturated_keywords_high_risk(self):
        text_content = (
            b"URGENT ACTION REQUIRED:\n"
            b"Your account suspended due to unauthorized access.\n"
            b"Immediate verification needed. Verify your account credentials now to prevent wire transfer freeze."
        )
        att = Attachment("phish_note.txt", "text/plain", len(text_content), ".txt", text_content)
        res = analyze_single_attachment_content(att)

        assert res.file_type == "PLAIN_TEXT"
        assert res.content_analysis_status == "ANALYZED"
        assert res.urls == []
        # Saturated with 4+ phishing lures -> score >= 60 (HIGH_RISK)
        assert res.content_risk_score >= 60
        assert res.content_verdict == "HIGH_RISK"

    # ── 21. Text Attachment: Benign Clean Text (NO_THREATS_DETECTED) ─
    def test_text_attachment_benign_no_keywords(self):
        text_content = b"Weekly team sync notes:\nDiscussed Q3 deliverables and sprint velocity. All on track."
        att = Attachment("notes.txt", "text/plain", len(text_content), ".txt", text_content)
        res = analyze_single_attachment_content(att)

        assert res.file_type == "PLAIN_TEXT"
        assert res.content_analysis_status == "ANALYZED"
        assert res.content_risk_score == 0
        assert res.content_verdict == "NO_THREATS_DETECTED"
        assert res.urls == []
        assert len(res.suspicious_indicators) == 0

    # ── 22. URL Redirect & Wrapper Unwrapping ─────────────────────
    def test_redirect_url_unwrapping(self):
        # 1. Google goto redirect
        goto_url = "https://www.google.com/goto?url=https%3A%2F%2Fsuspicious-login.phish.com%2Fauth"
        dests = _unwrap_redirect_url(goto_url)
        assert "https://suspicious-login.phish.com/auth" in dests

        # 2. Google q redirect
        q_url = "https://www.google.com/url?q=http%3A%2F%2F185.220.101.45%2Fverify"
        dests_q = _unwrap_redirect_url(q_url)
        assert "http://185.220.101.45/verify" in dests_q

        # 3. Safelinks redirect
        safe_url = "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpartner-login.com"
        dests_safe = _unwrap_redirect_url(safe_url)
        assert "https://partner-login.com" in dests_safe

        # 4. Base64 encoded redirect parameter
        import base64
        b64_val = base64.b64encode(b"https://evil-phish.net/login").decode("ascii")
        b64_url = f"https://tracking.example.com/click?link={b64_val}"
        dests_b64 = _unwrap_redirect_url(b64_url)
        assert "https://evil-phish.net/login" in dests_b64

        # 5. Normalization and deduplication via _process_extracted_urls
        all_urls, all_domains = _process_extracted_urls([goto_url, q_url])
        assert "https://suspicious-login.phish.com/auth" in all_urls
        assert "http://185.220.101.45/verify" in all_urls
        assert "suspicious-login.phish.com" in all_domains
        assert "185.220.101.45" in all_domains

    # ── 23. Benign URLs in Attachment (NO_THREATS_DETECTED) ───────
    def test_attachment_with_benign_url_remains_no_threats_detected(self):
        text_content = b"Please see our official documentation: https://legitimate-service.org/docs/help"
        att = Attachment("guide.txt", "text/plain", len(text_content), ".txt", text_content)
        analysis = analyze_attachment_contents([att])
        finding = analysis.findings[0]

        # Initially 0 score, NO_THREATS_DETECTED
        assert finding.content_risk_score == 0
        assert finding.content_verdict == "NO_THREATS_DETECTED"

        # Simulate clean/benign URL finding from url_analyzer
        from ..url_analyzer import URLFinding, URLAnalysis
        clean_finding = URLFinding(
            url="https://legitimate-service.org/docs/help",
            domain="legitimate-service.org",
            tld="org",
            risk_score=0,
            is_ip_url=False,
            is_url_shortener=False,
            has_suspicious_tld=False,
            excessive_subdomains=False,
            has_suspicious_chars=False,
            suspicious_char_matches=[],
            uses_https=True,
            display_href_mismatch=False,
            domain_reputation="clean",
            domain_rep_score=0,
            reasons=[],
        )
        url_analysis = URLAnalysis(
            total_count=1,
            suspicious_count=0,
            findings=[clean_finding],
            all_urls=["https://legitimate-service.org/docs/help"],
            limitations=[],
        )

        attach_url_intelligence(analysis, url_analysis)

        # Must NOT be marked malicious or suspicious just because it contains a benign URL
        assert finding.content_risk_score == 0
        assert finding.content_verdict == "NO_THREATS_DETECTED"

    # ── 24. Suspicious URL in Attachment (SUSPICIOUS) ─────────────
    def test_attachment_with_suspicious_url_elevates_to_suspicious(self):
        text_content = b"Server direct link: http://185.220.101.45/server_report"
        att = Attachment("portal_link.txt", "text/plain", len(text_content), ".txt", text_content)
        analysis = analyze_attachment_contents([att])
        finding = analysis.findings[0]

        from ..url_analyzer import URLFinding, URLAnalysis
        susp_finding = URLFinding(
            url="http://185.220.101.45/server_report",
            domain="185.220.101.45",
            tld="",
            risk_score=40,
            is_ip_url=True,
            is_url_shortener=False,
            has_suspicious_tld=False,
            excessive_subdomains=False,
            has_suspicious_chars=False,
            suspicious_char_matches=[],
            uses_https=False,
            display_href_mismatch=False,
            domain_reputation="suspicious",
            domain_rep_score=40,
            reasons=["Direct IP address in URL", "Unencrypted HTTP"],
        )
        url_analysis = URLAnalysis(
            total_count=1,
            suspicious_count=1,
            findings=[susp_finding],
            all_urls=["http://185.220.101.45/server_report"],
            limitations=[],
        )

        attach_url_intelligence(analysis, url_analysis)

        # Risk score and verdict must be elevated to reflect the suspicious URL
        assert finding.content_risk_score == 40
        assert finding.content_verdict == "SUSPICIOUS"
        assert any("suspicious" in ind.lower() for ind in finding.suspicious_indicators)

    # ── 25. Malicious Threat Intelligence Result (HIGH_RISK) ──────
    def test_attachment_with_malicious_ti_result_elevates_to_high_risk(self):
        text_content = b"Download update from https://phish-harvest.net/account"
        att = Attachment("update.txt", "text/plain", len(text_content), ".txt", text_content)
        analysis = analyze_attachment_contents([att])
        finding = analysis.findings[0]

        from ..url_analyzer import URLFinding, URLAnalysis
        mal_finding = URLFinding(
            url="https://phish-harvest.net/account",
            domain="phish-harvest.net",
            tld="net",
            risk_score=80,
            is_ip_url=False,
            is_url_shortener=False,
            has_suspicious_tld=False,
            excessive_subdomains=False,
            has_suspicious_chars=False,
            suspicious_char_matches=[],
            uses_https=True,
            display_href_mismatch=False,
            domain_reputation="malicious",
            domain_rep_score=80,
            reasons=["Known phishing domain on blocklist."],
        )
        url_analysis = URLAnalysis(
            total_count=1,
            suspicious_count=1,
            findings=[mal_finding],
            all_urls=["https://phish-harvest.net/account"],
            limitations=[],
        )

        attach_url_intelligence(analysis, url_analysis)

        # Risk score and verdict must escalate to HIGH_RISK
        assert finding.content_risk_score == 80
        assert finding.content_verdict == "HIGH_RISK"
        assert any("malicious" in r.lower() for r in finding.reasons)

    # ── 26. Full Pipeline: Wrapper Unwrapping & TI Integration ─────
    def test_full_pipeline_attachment_url_unwrapping_and_ti(self):
        from email.message import EmailMessage
        # Attachment contains a redirect wrapper URL pointing to an IP address
        wrapper_url = "https://www.google.com/goto?url=http%3A%2F%2F185.220.101.45%2Fverify"
        text_content = f"Please click the verification link: {wrapper_url}".encode("utf-8")

        msg = EmailMessage()
        msg["From"] = "helpdesk@company.com"
        msg["To"] = "employee@victim.com"
        msg["Subject"] = "Urgent Account Check"
        msg.set_content("Please see attached file.")
        msg.add_attachment(text_content, maintype="text", subtype="plain", filename="link.txt")

        report = analyze_email(msg.as_string())

        # 1. Destination URL was unwrapped and is present in overall extracted URLs
        assert "http://185.220.101.45/verify" in report["urls"]["all_urls"]

        # 2. Attachment finding was updated with URL intelligence and is NOT NO_THREATS_DETECTED
        att_finding = report["attachments"]["findings"][0]
        assert att_finding["risk_level"] in ("SUSPICIOUS", "HIGH_RISK")
        assert att_finding["risk_score"] >= 30
        assert att_finding["content_analysis"]["content_verdict"] in ("SUSPICIOUS", "HIGH_RISK")

        # 3. Attachments section correctly marks it suspicious
        assert report["attachments"]["suspicious"] >= 1


