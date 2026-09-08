"""
GmailGuard — FastAPI Interface Layer

Exposes the existing email-analysis pipeline as a REST API.
Does NOT contain any analysis logic — delegates entirely to main.analyze_email().

Endpoints:
    GET  /health   → service health check
    POST /analyze  → upload .eml file → full threat analysis JSON

Run:
    uvicorn api:app --reload
"""

from __future__ import annotations

import logging
import traceback
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from main import analyze_email

# ── Logging (no raw email bodies, no secrets) ─────────────────────
logger = logging.getLogger("gmailguard.api")

# ── Constants ─────────────────────────────────────────────────────
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB
ALLOWED_EXTENSIONS = {".eml"}
ALLOWED_CONTENT_TYPES = {
    "message/rfc822",
    "application/octet-stream",
    "text/plain",
}

# ── FastAPI Application ───────────────────────────────────────────
app = FastAPI(
    title="GmailGuard",
    description=(
        "AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform.\n\n"
        "Upload a raw `.eml` file and receive a comprehensive threat analysis report "
        "covering authentication, infrastructure, URL intelligence, PhishTank, "
        "NLP phishing classification, OSINT, and forensic evidence correlation."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS (development-friendly, production-safe) ──────────────────
_CORS_ORIGINS: list[str] = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ── Helpers ───────────────────────────────────────────────────────

def _safe_error(detail: str, status_code: int = 400) -> HTTPException:
    """Return an HTTPException that never leaks internals."""
    return HTTPException(status_code=status_code, detail=detail)


def _validate_upload(file: UploadFile, raw_bytes: bytes) -> None:
    """
    Validate file extension, content type, and size.
    Raises HTTPException on failure.
    """
    # Size check
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise _safe_error(
            f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
            status_code=413,
        )

    if len(raw_bytes) == 0:
        raise _safe_error("Uploaded file is empty.")

    # Extension check
    filename = (file.filename or "").lower()
    if filename:
        ext = ""
        dot_idx = filename.rfind(".")
        if dot_idx != -1:
            ext = filename[dot_idx:]
        if ext and ext not in ALLOWED_EXTENSIONS:
            raise _safe_error(
                f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            )

    # Content-type hint (lenient — many clients send application/octet-stream)
    ct = (file.content_type or "").lower()
    if ct and ct not in ALLOWED_CONTENT_TYPES:
        # Don't reject outright — some mail clients produce unusual MIME types.
        logger.info("Unusual content-type '%s' for file '%s'; proceeding anyway.", ct, filename)


# ── Endpoints ─────────────────────────────────────────────────────

@app.get(
    "/health",
    summary="Health Check",
    description="Returns service status. Use for uptime monitoring and readiness probes.",
    response_description="Service health status",
)
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "GmailGuard"}


@app.post(
    "/analyze",
    summary="Analyze Email",
    description=(
        "Upload a raw `.eml` (RFC 5322) email file for comprehensive threat analysis.\n\n"
        "The response includes:\n"
        "- **Threat score** (0–100) and verdict\n"
        "- Email authentication (SPF / DKIM / DMARC)\n"
        "- IP intelligence and geolocation\n"
        "- Domain intelligence\n"
        "- URL analysis and PhishTank results\n"
        "- Attachment analysis\n"
        "- ML/SVM phishing classification\n"
        "- Cross-vector evidence correlation\n"
        "- Forensic intelligence (OSINT, DNS history)\n"
    ),
    response_description="Complete GmailGuard threat analysis report",
)
async def analyze_email_endpoint(
    file: UploadFile = File(..., description="Raw .eml email file to analyze"),
) -> dict[str, Any]:
    """Accept a .eml upload, run the full GmailGuard pipeline, return JSON."""

    # ── Read & validate ───────────────────────────────────────────
    try:
        raw_bytes: bytes = await file.read()
    except Exception:
        raise _safe_error("Failed to read uploaded file.")

    _validate_upload(file, raw_bytes)

    # ── Decode to string (RFC 5322 is text) ───────────────────────
    try:
        raw_email = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise _safe_error("Failed to decode email file. Ensure UTF-8 encoding.")

    # ── Run the existing pipeline ─────────────────────────────────
    try:
        report = analyze_email(raw_email)
    except Exception as exc:
        logger.error("Analysis pipeline error: %s", type(exc).__name__, exc_info=True)
        raise _safe_error(
            "Internal analysis error. The email could not be processed.",
            status_code=500,
        )

    return report


# ── Global exception handler (catch-all safety net) ───────────────

@app.exception_handler(Exception)
async def _unhandled_exception_handler(request, exc):
    """Never leak stack traces, filesystem paths, or secrets."""
    logger.error("Unhandled exception: %s", type(exc).__name__, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred. Please try again."},
    )
