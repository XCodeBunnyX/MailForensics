"""Unit tests for email_parser.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from ..email_parser import parse_email, ParsedEmail


SIMPLE_EMAIL = """\
From: "Alice" <alice@example.com>
To: bob@example.com
Subject: Hello Bob
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <test.001@example.com>
Content-Type: text/plain; charset=UTF-8

Hello Bob, how are you?
"""

MULTIPART_EMAIL = """\
From: "Spammer" <spam@bad-domain.xyz>
To: victim@example.com
Subject: WIN A PRIZE
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <spam.001@bad-domain.xyz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=UTF-8

You have won! Click here: http://malicious.xyz/win

--boundary123
Content-Type: application/octet-stream; name="prize.exe"
Content-Disposition: attachment; filename="prize.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AAA==

--boundary123--
"""

REPLY_TO_EMAIL = """\
From: "CEO" <ceo@company.com>
Reply-To: attacker@gmail.com
To: finance@company.com
Subject: Wire Transfer
Date: Sun, 07 Sep 2026 10:00:00 +0000
Message-ID: <bec.001@company.com>
Content-Type: text/plain

Transfer money now.
"""


class TestEmailParser:
    def test_simple_parse_returns_parsed_email(self):
        result = parse_email(SIMPLE_EMAIL)
        assert isinstance(result, ParsedEmail)

    def test_sender_extraction(self):
        result = parse_email(SIMPLE_EMAIL)
        assert result.sender_email == "alice@example.com"
        assert result.sender_name == "Alice"
        assert result.sender_domain == "example.com"

    def test_subject_extraction(self):
        result = parse_email(SIMPLE_EMAIL)
        assert result.subject == "Hello Bob"

    def test_body_extraction(self):
        result = parse_email(SIMPLE_EMAIL)
        assert "Hello Bob" in result.text_body

    def test_multipart_attachment_extraction(self):
        result = parse_email(MULTIPART_EMAIL)
        assert len(result.attachments) == 1
        att = result.attachments[0]
        assert att.filename == "prize.exe"
        assert att.extension == ".exe"

    def test_multipart_text_body(self):
        result = parse_email(MULTIPART_EMAIL)
        assert "malicious.xyz" in result.text_body

    def test_reply_to_extraction(self):
        result = parse_email(REPLY_TO_EMAIL)
        assert "attacker@gmail.com" in result.reply_to

    def test_empty_email_no_crash(self):
        result = parse_email("")
        assert isinstance(result, ParsedEmail)

    def test_sender_domain_from_email(self):
        result = parse_email(MULTIPART_EMAIL)
        assert result.sender_domain == "bad-domain.xyz"

    def test_no_parse_errors_on_valid_email(self):
        result = parse_email(SIMPLE_EMAIL)
        assert len(result.parse_errors) == 0
