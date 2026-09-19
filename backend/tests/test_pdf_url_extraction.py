"""
Tests for PDF URL extraction in GmailGuard attachment_content_analyzer.py:
- Authoritative PDF hyperlink annotations (/URI)
- Line-wrapped URLs
- Duplicate URLs
- Text-only URLs
- Google redirect URLs
- Malformed URLs
- Exact count verification on test2.pdf fixture (= 2 unique URLs)
"""

import io
import os
import pytest
import pypdf

from backend.attachment_analyzer import Attachment
from backend.attachment_content_analyzer import (
    _analyze_pdf_content,
    _extract_pdf_urls,
    _clean_and_normalize_url,
    _is_valid_url,
    _process_extracted_urls,
)


def _create_minimal_pdf_with_annots(annot_urls: list[str], text_content: str = "") -> bytes:
    """Helper to generate a valid in-memory PDF with annotations and text."""
    writer = pypdf.PdfWriter()
    page = writer.add_blank_page(width=612, height=792)

    # Add text if provided
    # Note: pypdf blank page doesn't have text stream unless added, but we can mock or inject annotations
    for u in annot_urls:
        link_annot = pypdf.generic.DictionaryObject({
            pypdf.generic.NameObject("/Type"): pypdf.generic.NameObject("/Annot"),
            pypdf.generic.NameObject("/Subtype"): pypdf.generic.NameObject("/Link"),
            pypdf.generic.NameObject("/Rect"): pypdf.generic.ArrayObject([
                pypdf.generic.FloatObject(72),
                pypdf.generic.FloatObject(700),
                pypdf.generic.FloatObject(300),
                pypdf.generic.FloatObject(720),
            ]),
            pypdf.generic.NameObject("/A"): pypdf.generic.DictionaryObject({
                pypdf.generic.NameObject("/S"): pypdf.generic.NameObject("/URI"),
                pypdf.generic.NameObject("/URI"): pypdf.generic.TextStringObject(u),
            }),
        })
        writer.add_annotation(page_number=0, annotation=link_annot)

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


class TestPdfUrlExtraction:
    """Test suite for PDF URL extraction accuracy."""

    def test_fixture_test2_pdf_exact_count(self):
        """
        Verify the problematic test2.pdf fixture contains EXACTLY 2 unique URLs.
        Previously, line-wrapped visible text caused 4 URLs to be reported.
        """
        fixture_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "test2.pdf")
        assert os.path.exists(fixture_path), f"Fixture not found at {fixture_path}"

        with open(fixture_path, "rb") as f:
            pdf_bytes = f.read()

        att = Attachment(
            filename="test2.pdf",
            content_type="application/pdf",
            size_bytes=len(pdf_bytes),
            extension=".pdf",
            content=pdf_bytes,
        )

        finding = _analyze_pdf_content(att)

        # Inspection of test2.pdf reveals exactly 2 unique /URI targets across 5 line-wrapped annot rects
        assert len(finding.urls) == 2, f"Expected exactly 2 unique URLs, got {len(finding.urls)}: {finding.urls}"
        assert any("CAESUQHrOzAVTJ0L" in u for u in finding.urls)
        assert any("CAESXQHrOzAVqT7u" in u for u in finding.urls)
        # Verify no truncated fragments were retained
        for u in finding.urls:
            assert not u.endswith("CAESUQHrOzAVTJ0LwsCtbL7S4i9ruxchNSfLBtpToY2Q7")
            assert not u.endswith("CAESXQHrOzAVqT7u7taX1sbHRL2sn4XvhFtd7EFH9VN")

    def test_pdf_hyperlink_annotations_extracted(self):
        """PDF /Annots /URI targets are extracted as primary ground truth."""
        test_url = "https://legit-portal.example.com/login?session=active123"
        pdf_bytes = _create_minimal_pdf_with_annots([test_url])

        att = Attachment(
            filename="annot_test.pdf",
            content_type="application/pdf",
            size_bytes=len(pdf_bytes),
            extension=".pdf",
            content=pdf_bytes,
        )

        finding = _analyze_pdf_content(att)
        assert test_url in finding.urls
        assert len(finding.urls) == 1

    def test_line_wrapped_urls_reassembled(self):
        """Line-wrapped URLs across text lines are reassembled and not fragmented."""
        wrapped_text = (
            "Please visit our customer portal at:\n"
            "https://secure.example.com/auth/verify?token=abcdef\n"
            "1234567890xyz\n"
            "for complete information."
        )
        extracted = _extract_pdf_urls(
            annot_uris=[],
            text_chunks=[wrapped_text],
        )
        assert len(extracted) == 1
        assert extracted[0] == "https://secure.example.com/auth/verify?token=abcdef1234567890xyz"

    def test_duplicate_urls_deduplicated(self):
        """Identical URLs appearing multiple times in annots and text are deduplicated."""
        dup_url = "https://www.example.com/same-landing-page"
        text = f"Click here: {dup_url} or visit {dup_url} again."
        extracted = _extract_pdf_urls(
            annot_uris=[dup_url, dup_url],
            text_chunks=[text],
        )
        norm_urls, domains = _process_extracted_urls(extracted)
        assert len(norm_urls) == 1
        assert norm_urls[0] == dup_url
        assert domains == ["www.example.com"]

    def test_text_only_urls_without_annotations(self):
        """PDFs with no hyperlink annotations still correctly extract text URLs."""
        text = "Contact support at https://help.service.org/tickets/new or http://status.service.org"
        extracted = _extract_pdf_urls(
            annot_uris=[],
            text_chunks=[text],
        )
        norm_urls, domains = _process_extracted_urls(extracted)
        assert len(norm_urls) == 2
        assert "https://help.service.org/tickets/new" in norm_urls
        assert "http://status.service.org" in norm_urls
        assert sorted(domains) == ["help.service.org", "status.service.org"]

    def test_google_redirect_urls_not_fragmented(self):
        """Google redirect URLs with long query strings are not split into multiple URLs."""
        full_google_url = (
            "https://www.google.com/goto?url="
            "CAESUQHrOzAVTJ0LwsCtbL7S4i9ruxchNSfLBtpToY2Q7ynK0mI_Jr9Ed7azkLHUu4K0WCRvzSIXwCVb9NIJs9lEfSa8xnltB1hnwb1ao-1l_ZC6Qg"
        )
        # Simulate text where the URL wrapped at 80 characters
        split_text = (
            "https://www.google.com/goto?url=CAESUQHrOzAVTJ0LwsCtbL7S4i9ruxchNSfLBtpToY2Q7\n"
            "ynK0mI_Jr9Ed7azkLHUu4K0WCRvzSIXwCVb9NIJs9lEfSa8xnltB1hnwb1ao-1l_ZC6Qg\n"
        )
        extracted = _extract_pdf_urls(
            annot_uris=[full_google_url],
            text_chunks=[split_text],
        )
        norm_urls, domains = _process_extracted_urls(extracted)
        assert len(norm_urls) == 1
        assert norm_urls[0] == full_google_url

    def test_malformed_urls_discarded(self):
        """Malformed strings like http:// or invalid domains are rejected."""
        assert not _is_valid_url("http://")
        assert not _is_valid_url("https://.")
        assert not _is_valid_url("http:///path")
        assert not _is_valid_url("not_a_url")
        assert not _is_valid_url("http:// space in host /")
        assert _is_valid_url("https://example.com")
        assert _is_valid_url("http://192.168.1.1/test")

        text = "Check http:// and https://. and valid https://legit.org/index.html"
        extracted = _extract_pdf_urls(annot_uris=[], text_chunks=[text])
        assert len(extracted) == 1
        assert extracted[0] == "https://legit.org/index.html"

    def test_no_manufactured_urls_from_unrelated_text(self):
        """Adjacent English words across lines are never joined into fake URLs."""
        text = (
            "The email server protocol is HTTP/1.1 over TLS.\n"
            "Next line contains ordinary text without schemes.\n"
            "Visit us at https://company.com for details."
        )
        extracted = _extract_pdf_urls(annot_uris=[], text_chunks=[text])
        assert len(extracted) == 1
        assert extracted[0] == "https://company.com"
