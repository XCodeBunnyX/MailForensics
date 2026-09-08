"""
GmailGuard — FastAPI Endpoint Tests

Tests:
1. GET /health
2. POST /analyze with a valid .eml
3. POST /analyze with an invalid file
4. POST /analyze with an unsupported file type (.pdf)
5. POST /analyze with empty file
6. Correct JSON response structure (threat_score, verdict, etc.)
7. Backend analysis failure returns 500
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api import app

client = TestClient(app)


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def phishing_eml() -> bytes:
    """Load the phishing sample .eml as raw bytes."""
    p = Path("sample_emails/phishing_bank.eml")
    if not p.exists():
        pytest.skip("Sample phishing email not found")
    return p.read_bytes()


@pytest.fixture
def legitimate_eml() -> bytes:
    """Load the legitimate sample .eml as raw bytes."""
    p = Path("sample_emails/legitimate.eml")
    if not p.exists():
        pytest.skip("Sample legitimate email not found")
    return p.read_bytes()


# ── 1. Health Check ───────────────────────────────────────────────

class TestHealthEndpoint:

    def test_health_returns_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "GmailGuard"

    def test_health_is_json(self):
        resp = client.get("/health")
        assert resp.headers["content-type"].startswith("application/json")


# ── 2. Analyze — Valid .eml ───────────────────────────────────────

class TestAnalyzeValidEmail:

    def test_phishing_eml_returns_200(self, phishing_eml):
        resp = client.post(
            "/analyze",
            files={"file": ("phishing.eml", phishing_eml, "message/rfc822")},
        )
        assert resp.status_code == 200

    def test_legitimate_eml_returns_200(self, legitimate_eml):
        resp = client.post(
            "/analyze",
            files={"file": ("legit.eml", legitimate_eml, "message/rfc822")},
        )
        assert resp.status_code == 200

    def test_response_has_required_fields(self, phishing_eml):
        resp = client.post(
            "/analyze",
            files={"file": ("test.eml", phishing_eml, "message/rfc822")},
        )
        data = resp.json()
        # Core fields produced by the existing pipeline
        assert "threat_score" in data
        assert "verdict" in data
        assert "email" in data
        assert "authentication" in data
        assert "ml" in data
        assert "urls" in data
        assert "attachments" in data
        assert "evidence" in data
        assert "forensics" in data
        assert "limitations" in data

    def test_threat_score_is_int_in_range(self, phishing_eml):
        resp = client.post(
            "/analyze",
            files={"file": ("test.eml", phishing_eml, "message/rfc822")},
        )
        score = resp.json()["threat_score"]
        assert isinstance(score, int)
        assert 0 <= score <= 100

    def test_verdict_is_string(self, phishing_eml):
        resp = client.post(
            "/analyze",
            files={"file": ("test.eml", phishing_eml, "message/rfc822")},
        )
        assert isinstance(resp.json()["verdict"], str)

    def test_octet_stream_content_type_accepted(self, phishing_eml):
        """Many upload tools send application/octet-stream."""
        resp = client.post(
            "/analyze",
            files={"file": ("test.eml", phishing_eml, "application/octet-stream")},
        )
        assert resp.status_code == 200


# ── 3. Analyze — Invalid File ────────────────────────────────────

class TestAnalyzeInvalidInput:

    def test_no_file_returns_422(self):
        resp = client.post("/analyze")
        assert resp.status_code == 422

    def test_empty_file_returns_400(self):
        resp = client.post(
            "/analyze",
            files={"file": ("empty.eml", b"", "message/rfc822")},
        )
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()


# ── 4. Analyze — Unsupported File Type ───────────────────────────

class TestAnalyzeUnsupportedFileType:

    def test_pdf_extension_rejected(self):
        resp = client.post(
            "/analyze",
            files={"file": ("report.pdf", b"fake pdf content", "application/pdf")},
        )
        assert resp.status_code == 400
        assert ".eml" in resp.json()["detail"]

    def test_exe_extension_rejected(self):
        resp = client.post(
            "/analyze",
            files={"file": ("malware.exe", b"\x00\x01", "application/octet-stream")},
        )
        assert resp.status_code == 400

    def test_zip_extension_rejected(self):
        resp = client.post(
            "/analyze",
            files={"file": ("archive.zip", b"PK\x03\x04", "application/zip")},
        )
        assert resp.status_code == 400


# ── 5. Backend Analysis Failure ───────────────────────────────────

class TestAnalysisFailure:

    def test_pipeline_exception_returns_500(self):
        """If the analysis pipeline throws, the API returns 500 without leaking internals."""
        with patch("api.analyze_email", side_effect=RuntimeError("kaboom")):
            resp = client.post(
                "/analyze",
                files={"file": ("crash.eml", b"From: x@y.com\nSubject: test\n\nBody", "message/rfc822")},
            )
            assert resp.status_code == 500
            body = resp.json()
            assert "kaboom" not in body.get("detail", "")
            assert "traceback" not in body.get("detail", "").lower()


# ── 6. JSON Serialization ────────────────────────────────────────

class TestResponseSerialization:

    def test_response_is_valid_json(self, phishing_eml):
        resp = client.post(
            "/analyze",
            files={"file": ("test.eml", phishing_eml, "message/rfc822")},
        )
        # .json() would raise if not valid JSON
        data = resp.json()
        assert isinstance(data, dict)

    def test_phishtank_in_forensics(self, phishing_eml):
        resp = client.post(
            "/analyze",
            files={"file": ("test.eml", phishing_eml, "message/rfc822")},
        )
        forensics = resp.json().get("forensics", {})
        assert "phishtank" in forensics


# ── 7. CORS Headers ──────────────────────────────────────────────

class TestCORS:

    def test_cors_allows_localhost_3000(self):
        resp = client.options(
            "/analyze",
            headers={
                "origin": "http://localhost:3000",
                "access-control-request-method": "POST",
            },
        )
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"

    def test_cors_allows_localhost_5173(self):
        resp = client.options(
            "/analyze",
            headers={
                "origin": "http://localhost:5173",
                "access-control-request-method": "POST",
            },
        )
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"

    def test_cors_blocks_unknown_origin(self):
        resp = client.options(
            "/analyze",
            headers={
                "origin": "http://evil.example.com",
                "access-control-request-method": "POST",
            },
        )
        assert resp.headers.get("access-control-allow-origin") is None
