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
import time
import traceback
import urllib.parse
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .main import analyze_email

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

# ── Request Models ────────────────────────────────────────────────
class AnalyzeTextRequest(BaseModel):
    raw_email: str | None = None
    email_text: str | None = None

    def get_text(self) -> str:
        return self.raw_email or self.email_text or ""


class URLSandboxRequest(BaseModel):
    url: str
    force_live: bool = False


class GeminiAnalysisRequest(BaseModel):
    raw_email: str | None = None
    report: dict[str, Any] | None = None

GeminiAnalysisRequest.model_rebuild()

# ── FastAPI Application ───────────────────────────────────────────
app = FastAPI(
    title="GmailGuard",
    description=(
        "AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform.\n\n"
        "Upload a raw `.eml` file or submit raw email text and receive a comprehensive threat "
        "analysis report covering authentication, infrastructure, URL intelligence, PhishTank, "
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
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    """Ensure development static files (JS, CSS, HTML) are never cached by browsers."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith(("/js", "/css", "/assets")):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response



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


@app.post(
    "/analyze-text",
    response_model=dict[str, Any],
    summary="Analyze raw RFC 5322 email string",
    description="Accepts a raw RFC 5322 email string as JSON payload and returns the full threat analysis report.",
    response_description="Complete GmailGuard threat analysis report",
)
async def analyze_text_endpoint(payload: AnalyzeTextRequest) -> dict[str, Any]:
    """Accept raw email string directly in JSON body, run pipeline, return JSON."""
    raw_email = payload.get_text().strip()
    if not raw_email:
        raise _safe_error("Email content is empty.")

    if len(raw_email.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise _safe_error(
            f"Payload too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
            status_code=413,
        )

    try:
        report = analyze_email(raw_email)
    except Exception as exc:
        logger.error("Analysis pipeline error: %s", type(exc).__name__, exc_info=True)
        raise _safe_error(
            "Internal analysis error. The email could not be processed.",
            status_code=500,
        )

    return report


@app.post(
    "/sandbox/scan-url",
    response_model=dict[str, Any],
    summary="Dynamic URL Analysis (Local Browserless Sandbox)",
    description="Submit a URL for isolated dynamic browser investigation in local Browserless Chromium container.",
    response_description="Browserless dynamic sandbox forensic telemetry, screenshots, and behavioral findings",
)
async def sandbox_scan_url_endpoint(payload: URLSandboxRequest) -> dict[str, Any]:
    """Dynamically scan a URL via local Browserless Chromium container."""
    url = (payload.url or "").strip()
    if not url:
        raise _safe_error("URL cannot be empty.")
    try:
        from starlette.concurrency import run_in_threadpool
        from .url_sandbox import scan_url_dynamic
        finding = await run_in_threadpool(scan_url_dynamic, url, force_live=payload.force_live)
        return finding.to_dict()


    except Exception as exc:
        logger.error("URL sandbox error: %s", type(exc).__name__, exc_info=True)
        raise _safe_error("Failed to execute URL dynamic sandbox.", status_code=500)


# ── Gmail API & OAuth 2.0 Endpoints ────────────────────────────────

@app.get(
    "/api/gmail/status",
    summary="Gmail Account Connection Status",
    description="Check whether a real Gmail account is connected via OAuth 2.0.",
)
async def gmail_status_endpoint() -> dict[str, Any]:
    from .gmail_service import gmail_service
    from starlette.concurrency import run_in_threadpool
    user_info = await run_in_threadpool(gmail_service.get_user_info)
    return user_info


@app.get(
    "/api/gmail/auth",
    summary="Start Google OAuth 2.0 Flow",
    description="Initiate Google OAuth 2.0 consent flow by redirecting to Google authorization URL.",
)
async def gmail_auth_endpoint(redirect_uri: str | None = None):
    from .gmail_service import gmail_service
    from starlette.concurrency import run_in_threadpool
    from fastapi.responses import RedirectResponse
    try:
        auth_url, _ = await run_in_threadpool(gmail_service.get_authorization_url, redirect_uri)
        return RedirectResponse(url=auth_url)
    except Exception as exc:
        logger.error("Failed to start Google OAuth flow: %s", exc)
        raise _safe_error(f"Google OAuth configuration error: {exc}", status_code=500)


@app.get(
    "/api/gmail/auth-url",
    summary="Generate Google OAuth 2.0 Authorization URL",
    description="Generate Google OAuth 2.0 consent URL requesting least-privilege gmail.readonly scope.",
)
async def gmail_auth_url_endpoint(redirect_uri: str | None = None) -> dict[str, Any]:
    from .gmail_service import gmail_service
    from starlette.concurrency import run_in_threadpool
    try:
        auth_url, state = await run_in_threadpool(gmail_service.get_authorization_url, redirect_uri)
        return {"auth_url": auth_url, "state": state}
    except Exception as exc:
        logger.error("Failed to generate Google OAuth URL: %s", exc)
        raise _safe_error(f"Google OAuth configuration error: {exc}", status_code=500)


@app.get(
    "/api/gmail/oauth2callback",
    summary="Google OAuth 2.0 Web Callback",
    description="Handle OAuth redirect callback from Google, exchange code for credentials, redirect to dashboard.",
)
@app.get(
    "/api/gmail/oauth2callback/",
    include_in_schema=False,
)
async def gmail_oauth2callback_endpoint(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    from .gmail_service import gmail_service
    from starlette.concurrency import run_in_threadpool
    from fastapi.responses import RedirectResponse

    # Fallback to request query_params if parameter binding missed anything
    code = code or request.query_params.get("code")
    state = state or request.query_params.get("state")
    error = error or request.query_params.get("error")

    logger.info("OAuth callback hit: code_present=%s, state=%s, error=%s", bool(code), state, error)

    if error:
        logger.warning("Google OAuth error from consent screen: %s", error)
        return RedirectResponse(url=f"/?gmail=error&reason={error}")

    # Check if already authenticated (handles duplicate browser requests)
    if not code:
        if gmail_service.is_authenticated():
            logger.info("No code supplied but Gmail session is already authenticated; redirecting to connected.")
            return RedirectResponse(url="/?gmail=connected")
        logger.warning("Missing authorization code from Google OAuth callback.")
        return RedirectResponse(url="/?gmail=error&reason=missing_code")

    try:
        await run_in_threadpool(gmail_service.handle_oauth_callback, code, state)
        return RedirectResponse(url="/?gmail=connected")
    except Exception as exc:
        logger.error("OAuth token exchange failed: %s", exc, exc_info=True)
        if gmail_service.is_authenticated():
            logger.info("Gmail credentials valid despite callback exception; redirecting to connected.")
            return RedirectResponse(url="/?gmail=connected")

        # Record diagnostics safely to debug log
        try:
            debug_log = Path(__file__).resolve().parent / "oauth_debug.log"
            with open(debug_log, "a", encoding="utf-8") as df:
                df.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Callback token exchange error: {type(exc).__name__}: {exc}\n{traceback.format_exc()}\n")
        except Exception:
            pass

        err_clean = str(exc).replace("\n", " ").strip()[:120]
        encoded_details = urllib.parse.quote(err_clean)
        return RedirectResponse(url=f"/?gmail=error&reason=exchange_failed&details={encoded_details}")


@app.post(
    "/api/gmail/callback",
    summary="Direct Code Exchange Callback",
    description="Exchange OAuth authorization code for credentials via API JSON request.",
)
async def gmail_direct_callback_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
    from .gmail_service import gmail_service
    from starlette.concurrency import run_in_threadpool
    code = payload.get("code")
    if not code:
        raise _safe_error("Authorization code is required.")
    try:
        result = await run_in_threadpool(
            gmail_service.handle_oauth_callback,
            code,
            payload.get("state"),
            payload.get("redirect_uri"),
        )
        return result
    except Exception as exc:
        logger.error("Direct OAuth callback failed: %s", exc)
        raise _safe_error(f"Token exchange failed: {exc}", status_code=500)


@app.post(
    "/api/gmail/disconnect",
    summary="Disconnect Gmail Account",
    description="Revoke and delete server-side OAuth credentials for the connected Gmail account.",
)
async def gmail_disconnect_endpoint() -> dict[str, Any]:
    from .gmail_service import gmail_service
    from starlette.concurrency import run_in_threadpool
    success = await run_in_threadpool(gmail_service.disconnect)
    return {"connected": False, "success": success, "message": "Gmail account disconnected."}


@app.get(
    "/api/gmail/messages",
    summary="List Gmail Inbox Messages",
    description="Retrieve user messages with envelope metadata, read states, attachments/URL flags, and cached threat scores.",
)
async def gmail_list_messages_endpoint(
    max_results: int = 25,
    query: str | None = None,
    page_token: str | None = None,
) -> dict[str, Any]:
    from .gmail_service import gmail_service
    from starlette.concurrency import run_in_threadpool
    try:
        result = await run_in_threadpool(
            gmail_service.list_messages,
            max_results=max_results,
            query=query,
            page_token=page_token,
        )
        return result
    except Exception as exc:
        logger.error("Error listing Gmail messages: %s", exc, exc_info=True)
        raise _safe_error(f"Failed to list messages: {exc}", status_code=500)


@app.post(
    "/api/gmail/analyze/{message_id}",
    summary="Analyze Specific Gmail Message On-Demand",
    description="Retrieve complete email from Gmail API in raw RFC 5322 format, execute forensic pipeline and Gemini security layer, cache and return report.",
)
async def gmail_analyze_message_endpoint(
    message_id: str,
    reanalyze: bool = False,
) -> dict[str, Any]:
    from .gmail_service import gmail_service
    from starlette.concurrency import run_in_threadpool

    clean_id = message_id.strip()
    if not clean_id:
        raise _safe_error("Message ID cannot be empty.")

    # Check cache first unless reanalyze is requested
    if not reanalyze:
        cached = await run_in_threadpool(gmail_service.get_cached_analysis, clean_id)
        if cached:
            logger.info("Returning cached analysis for Gmail message %s", clean_id)
            return cached

    # Retrieve complete raw RFC 5322 email string
    try:
        raw_email = await run_in_threadpool(gmail_service.get_message_raw, clean_id)
    except Exception as exc:
        logger.error("Failed to retrieve raw message %s: %s", clean_id, exc)
        raise _safe_error(f"Failed to retrieve email content from Gmail: {exc}", status_code=502)

    if not raw_email or not raw_email.strip():
        raise _safe_error("Retrieved email content was empty.", status_code=502)

    # Execute existing GmailGuard core forensic pipeline
    try:
        report = await run_in_threadpool(analyze_email, raw_email)
    except Exception as exc:
        logger.error("Forensic pipeline failed on Gmail message %s: %s", clean_id, exc, exc_info=True)
        raise _safe_error("Forensic analysis pipeline failed to process message.", status_code=500)

    # Attach message ID metadata and persist in cache
    report["gmail_message_id"] = clean_id
    await run_in_threadpool(gmail_service.save_cached_analysis, clean_id, report)

    return report


@app.get(
    "/api/gmail/analysis/{message_id}",
    summary="Get Cached Analysis for Gmail Message",
    description="Retrieve existing forensic report for a message without re-running analysis.",
)
async def gmail_get_cached_analysis_endpoint(message_id: str) -> dict[str, Any]:
    from .gmail_service import gmail_service
    from starlette.concurrency import run_in_threadpool
    cached = await run_in_threadpool(gmail_service.get_cached_analysis, message_id)
    if not cached:
        raise HTTPException(status_code=404, detail="No cached analysis found for this message.")
    return cached


# ── Gemini AI Security & Overview Endpoints ───────────────────────

@app.get(
    "/api/gemini/status",
    summary="Gemini AI Security Service Status",
    description="Check whether Gemini AI service is configured and ready.",
)
async def gemini_security_status_endpoint() -> dict[str, Any]:
    from .gemini_security import is_gemini_available, _get_api_key
    from . import config
    has_key = bool(_get_api_key())
    return {
        "configured": has_key,
        "available": is_gemini_available(),
        "model": getattr(config, "GEMINI_MODEL", "gemini-3.5-flash"),
        "candidate_models": getattr(config, "GEMINI_CANDIDATE_MODELS", []),
        "service": "Google GenAI SDK",
    }


@app.get(
    "/api/gemini/overview",
    summary="Gemini Mailbox Security Overview",
    description="Aggregate security metrics and common patterns across all analyzed emails in mailbox.",
)
async def gemini_mailbox_overview_endpoint() -> dict[str, Any]:
    from .gmail_service import gmail_service
    from .gemini_security import generate_mail_security_overview
    from starlette.concurrency import run_in_threadpool

    cached_reports = await run_in_threadpool(gmail_service.list_all_cached_analyses)
    overview = await run_in_threadpool(generate_mail_security_overview, cached_reports)
    return overview


@app.post(
    "/api/gemini/analyze",
    summary="Contextual Gemini AI Threat Reasoning",
    description="Run or re-run contextual human-readable security assessment on email content and forensic report.",
)
async def gemini_security_analyze_endpoint(payload: GeminiAnalysisRequest) -> dict[str, Any]:
    from .gemini_security import analyze_email_security
    from starlette.concurrency import run_in_threadpool
    try:
        return await run_in_threadpool(
            analyze_email_security,
            raw_email=payload.raw_email,
            report=payload.report,
        )
    except Exception as exc:
        logger.error("Gemini security analysis endpoint error: %s", exc, exc_info=True)
        raise _safe_error(f"Gemini analysis service error: {exc}", status_code=500)


# Backwards compatibility endpoints
@app.get("/ai/status", include_in_schema=False)
async def legacy_ai_status_endpoint():
    return await gemini_security_status_endpoint()


@app.post("/ai/gemini-analyze", include_in_schema=False)
async def legacy_ai_analyze_endpoint(payload: GeminiAnalysisRequest):
    return await gemini_security_analyze_endpoint(payload)


# ── Static Frontend & Screenshots Mount ───────────────────────────
FRONTEND_DIR = Path(__file__).resolve().parent.parent
SCREENSHOTS_DIR = Path(__file__).resolve().parent / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/screenshots", StaticFiles(directory=str(SCREENSHOTS_DIR)), name="screenshots")

if (FRONTEND_DIR / "css").exists():
    app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
if (FRONTEND_DIR / "js").exists():
    app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")
if (FRONTEND_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR / "assets")), name="assets")



@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the MailForensics web dashboard directly from FastAPI."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return JSONResponse({"status": "ok", "service": "GmailGuard"})


# ── Global exception handler (catch-all safety net) ───────────────

@app.exception_handler(Exception)
async def _unhandled_exception_handler(request, exc):
    """Never leak stack traces, filesystem paths, or secrets."""
    logger.error("Unhandled exception: %s", type(exc).__name__, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred. Please try again."},
    )
