"""
GmailGuard — URL Dynamic Analysis Sandbox (urlscan.io)

Submits extracted URLs to the remote urlscan.io cloud sandbox, polls for
the rendered execution result, and extracts dynamic behavioral indicators.

SECURITY RULE:
  - Suspicious URLs are NEVER requested, visited, or executed on the local host.
  - All rendering and JavaScript execution occurs strictly within the remote
    isolated urlscan.io sandbox environment.
  - API keys are loaded exclusively from environment variables (.env) and
    never hardcoded or exposed in logs/reports.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from . import config

logger = logging.getLogger("gmailguard.url_sandbox")


# ═══════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class URLScanFinding:
    """Findings from a remote dynamic urlscan.io sandbox execution."""
    submitted_url: str
    scan_uuid: str = ""
    result_url: str = ""
    screenshot_url: str = ""
    dom_url: str = ""
    effective_url: str = ""
    status: str = "PENDING"       # "COMPLETED" | "TIMEOUT" | "ERROR" | "SKIPPED"
    verdict: str = "UNKNOWN"      # "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "UNKNOWN"
    mode: str = "LIVE"            # "LIVE" | "MOCK"
    malicious_score: int = 0      # 0 to 100
    is_malicious: bool = False
    content_category: Optional[str] = None  # e.g. "ADULT_CONTENT"
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    page_info: dict[str, Any] = field(default_factory=dict)
    redirects: list[dict[str, Any]] = field(default_factory=list)
    contacted_domains: list[str] = field(default_factory=list)
    contacted_ips: list[str] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    behavior_indicators: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "submitted_url": self.submitted_url,
            "scan_uuid": self.scan_uuid,
            "result_url": self.result_url,
            "screenshot_url": self.screenshot_url,
            "dom_url": self.dom_url,
            "effective_url": self.effective_url,
            "status": self.status,
            "verdict": self.verdict,
            "mode": self.mode,
            "malicious_score": self.malicious_score,
            "is_malicious": self.is_malicious,
            "content_category": self.content_category,
            "categories": self.categories,
            "tags": self.tags,
            "page_info": self.page_info,
            "redirects": self.redirects,
            "contacted_domains": self.contacted_domains,
            "contacted_ips": self.contacted_ips,
            "downloads": self.downloads,
            "behavior_indicators": self.behavior_indicators,
            "reasons": self.reasons,
            "error": self.error,
        }


@dataclass
class URLSandboxAnalysis:
    """Aggregated dynamic sandbox analysis for all scanned URLs."""
    total_scanned: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    mode: str = "LIVE"            # "LIVE" | "MOCK"
    findings: list[URLScanFinding] = field(default_factory=list)
    source: str = "urlscan.io Dynamic Sandbox"
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_scanned": self.total_scanned,
            "malicious_count": self.malicious_count,
            "suspicious_count": self.suspicious_count,
            "mode": self.mode,
            "findings": [f.to_dict() for f in self.findings],
            "source": self.source,
            "limitations": self.limitations,
        }


# ═══════════════════════════════════════════════════════════════════
# URLSCAN.IO API CLIENT
# ═══════════════════════════════════════════════════════════════════

def submit_scan(
    url: str,
    api_key: Optional[str] = None,
    visibility: str = "unlisted",
    timeout: int = 15,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Submit a URL to urlscan.io for remote execution.

    Args:
        url: Target URL to scan remotely.
        api_key: urlscan.io API key (defaults to config.URLSCAN_API_KEY).
        visibility: 'unlisted', 'private', or 'public'.
        timeout: Network timeout in seconds.

    Returns:
        (scan_uuid, result_url, error_message)
    """
    key = api_key if api_key is not None else getattr(config, "URLSCAN_API_KEY", "")
    if not key:
        return None, None, "urlscan.io API key is not configured in .env"

    clean_url = (url or "").strip()
    if not clean_url:
        return None, None, "URL is empty"
    if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
        clean_url = "http://" + clean_url

    submit_url = getattr(config, "URLSCAN_SUBMIT_URL", "https://urlscan.io/api/v1/scan/")
    headers = {
        "API-Key": key,
        "Content-Type": "application/json",
        "User-Agent": "GmailGuard-Sandbox/1.0",
    }
    payload = json.dumps({
        "url": clean_url,
        "visibility": visibility,
    }).encode("utf-8")

    req = urllib.request.Request(submit_url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            scan_uuid = data.get("uuid")
            result_url = data.get("result") or data.get("api")
            return scan_uuid, result_url, None
    except urllib.error.HTTPError as err:
        body = ""
        try:
            body = err.read().decode("utf-8")
            err_json = json.loads(body)
            msg = err_json.get("message", err.reason)
        except Exception:
            msg = err.reason

        if err.code == 429:
            return None, None, f"urlscan.io rate limit reached (HTTP 429): {msg}"
        elif err.code in (401, 403):
            return None, None, f"urlscan.io authentication error (HTTP {err.code}): {msg}"
        elif err.code == 400:
            return None, None, f"urlscan.io rejected submission (HTTP 400): {msg}"
        return None, None, f"urlscan.io HTTP error {err.code}: {msg}"
    except urllib.error.URLError as err:
        return None, None, f"Network connection failed: {err.reason}"
    except Exception as exc:
        return None, None, f"Submission error: {type(exc).__name__} - {str(exc)}"


def poll_scan_result(
    uuid: str,
    api_key: Optional[str] = None,
    max_wait_s: int = 45,
    poll_interval_s: float = 3.0,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """
    Poll urlscan.io until the scan completes or times out.

    Args:
        uuid: Scan UUID returned by submit_scan.
        api_key: urlscan.io API key.
        max_wait_s: Maximum seconds to wait.
        poll_interval_s: Seconds between poll attempts.

    Returns:
        (result_dict, error_message)
    """
    if not uuid:
        return None, "Invalid scan UUID"

    key = api_key if api_key is not None else getattr(config, "URLSCAN_API_KEY", "")
    result_base = getattr(config, "URLSCAN_RESULT_BASE_URL", "https://urlscan.io/api/v1/result/")
    endpoint = f"{result_base.rstrip('/')}/{uuid}/"

    headers = {"User-Agent": "GmailGuard-Sandbox/1.0"}
    if key:
        headers["API-Key"] = key

    start_time = time.time()

    while True:
        req = urllib.request.Request(endpoint, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data, None
        except urllib.error.HTTPError as err:
            # HTTP 404 indicates the scan is still running/queued
            if err.code == 404:
                elapsed = time.time() - start_time
                if elapsed >= max_wait_s:
                    return None, f"Scan timed out after {int(elapsed)}s while waiting for urlscan.io result"
                time.sleep(poll_interval_s)
                continue
            elif err.code == 429:
                return None, "urlscan.io rate limit reached during result polling"
            elif err.code in (401, 403):
                return None, f"urlscan.io result access denied (HTTP {err.code})"
            else:
                return None, f"urlscan.io result HTTP error {err.code}: {err.reason}"
        except urllib.error.URLError as err:
            return None, f"Network error polling result: {err.reason}"
        except Exception as exc:
            return None, f"Error polling result: {type(exc).__name__} - {str(exc)}"


# ═══════════════════════════════════════════════════════════════════
# EXTRACTION & ANALYSIS
# ═══════════════════════════════════════════════════════════════════

_SUSPICIOUS_DOWNLOAD_EXTENSIONS = {
    ".exe", ".scr", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".msi",
    ".zip", ".rar", ".7z", ".iso", ".img", ".apk", ".jar", ".hta",
}

_SUSPICIOUS_DOWNLOAD_MIMES = {
    "application/x-msdownload", "application/x-dosexec", "application/octet-stream",
    "application/x-msdos-program", "application/zip", "application/x-zip-compressed",
    "application/x-iso9660-image", "application/vnd.android.package-archive",
}


def extract_sandbox_findings(
    submitted_url: str,
    scan_uuid: str,
    data: dict[str, Any],
) -> URLScanFinding:
    """
    Parse a completed urlscan.io result payload into a structured URLScanFinding.
    """
    reasons: list[str] = []
    behavior_indicators: list[str] = []
    downloads: list[dict[str, Any]] = []

    # ── Task metadata ─────────────────────────────────────────────
    task = data.get("task", {})
    result_url = task.get("reportURL") or f"https://urlscan.io/result/{scan_uuid}/"
    screenshot_url = task.get("screenshotURL") or f"https://urlscan.io/screenshots/{scan_uuid}.png"
    dom_url = task.get("domURL") or f"https://urlscan.io/dom/{scan_uuid}/"

    # ── Page info ─────────────────────────────────────────────────
    page = data.get("page", {})
    effective_url = page.get("url") or submitted_url
    status_code = page.get("status")

    page_info: dict[str, Any] = {
        "url": effective_url,
        "domain": page.get("domain", ""),
        "ip": page.get("ip", ""),
        "country": page.get("country", ""),
        "city": page.get("city", ""),
        "server": page.get("server", ""),
        "status_code": status_code,
        "title": page.get("title", ""),
        "asn_name": page.get("asnname", ""),
        "tls_issuer": page.get("tlsIssuer", ""),
        "ptr": page.get("ptr", ""),
    }

    # ── Lists (contacted domains & IPs) ───────────────────────────
    lists = data.get("lists", {})
    contacted_domains = list(dict.fromkeys(lists.get("domains", [])))
    contacted_ips = list(dict.fromkeys(lists.get("ips", [])))

    # ── Redirects & Navigation chain ──────────────────────────────
    raw_redirects = data.get("data", {}).get("redirects", [])
    redirect_chain: list[dict[str, Any]] = []
    if raw_redirects:
        for r in raw_redirects:
            if isinstance(r, dict):
                redirect_chain.append(r)
            elif isinstance(r, str):
                redirect_chain.append({"url": r})

    # Check for mismatch between submitted URL and final rendered URL
    norm_submitted = submitted_url.rstrip("/").lower()
    norm_effective = effective_url.rstrip("/").lower()
    if norm_submitted and norm_effective and norm_submitted != norm_effective:
        reasons.append(
            f"Dynamic navigation redirect detected: '{submitted_url}' redirected to '{effective_url}'."
        )

    # ── Downloads & Payload detection ─────────────────────────────
    requests = data.get("data", {}).get("requests", [])
    for req_item in requests:
        resp_obj = req_item.get("response", {})
        resp_inner = resp_obj.get("response", {}) if isinstance(resp_obj, dict) else {}
        mime = (resp_inner.get("mimeType") or resp_obj.get("mimeType") or "").lower()
        req_url = resp_inner.get("url") or req_item.get("request", {}).get("url") or ""
        headers = resp_inner.get("headers") or {}

        content_disp = headers.get("content-disposition", "") or headers.get("Content-Disposition", "")
        is_attachment_header = "attachment" in content_disp.lower()

        # Check for executable or payload extension in downloaded resource
        parsed_path = urllib.parse.urlparse(req_url).path.lower()
        has_susp_ext = any(parsed_path.endswith(ext) for ext in _SUSPICIOUS_DOWNLOAD_EXTENSIONS)
        has_susp_mime = mime in _SUSPICIOUS_DOWNLOAD_MIMES

        if is_attachment_header or has_susp_ext or (has_susp_mime and not mime.startswith("image/")):
            filename = ""
            if "filename=" in content_disp:
                filename = content_disp.split("filename=")[-1].strip('"\' ')
            elif parsed_path:
                filename = parsed_path.split("/")[-1]

            download_info = {
                "url": req_url,
                "mime_type": mime,
                "filename": filename,
                "hash": resp_obj.get("hash", ""),
                "size": resp_obj.get("size", 0),
            }
            # Deduplicate downloads by URL
            if not any(d["url"] == req_url for d in downloads):
                downloads.append(download_info)
                reasons.append(
                    f"URL triggered download of '{filename or 'resource'}' ({mime or 'unknown MIME'})."
                )

    # ── JavaScript & Behavioral indicators ────────────────────────
    console_msgs = data.get("data", {}).get("console", [])
    if console_msgs:
        errors = [m.get("message", {}).get("text", "") for m in console_msgs if m.get("message", {}).get("level") == "error"]
        if errors:
            behavior_indicators.append(f"Encountered {len(errors)} JavaScript console error(s) during sandbox execution.")

    # Detected web technologies / frameworks via Wappalyzer
    wappa_items = data.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", [])
    if wappa_items:
        tech_names = [t.get("app") for t in wappa_items if t.get("app")][:8]
        if tech_names:
            behavior_indicators.append(f"Sandbox detected web technologies: {', '.join(tech_names)}.")

    # Number of external requests
    if len(requests) > 30:
        behavior_indicators.append(f"High outbound network activity: generated {len(requests)} dynamic HTTP requests.")

    # ── Verdict & Scoring ─────────────────────────────────────────
    verdicts = data.get("verdicts", {})
    overall = verdicts.get("overall", {})
    urlscan_v = verdicts.get("urlscan", {})
    engines_v = verdicts.get("engines", {})

    malicious_score = overall.get("score", 0)
    is_malicious = bool(overall.get("malicious") or urlscan_v.get("malicious"))
    categories = list(overall.get("categories", [])) or list(urlscan_v.get("categories", []))
    tags = list(overall.get("tags", [])) or list(overall.get("brands", []))

    # ── Adult / Pornographic Content Signal ───────────────────────
    # Do NOT classify pornography = malware!
    # Explicitly check categories and tags for adult content indicators.
    _ADULT_KEYWORDS = {"adult", "pornography", "porn", "nsfw", "erotic", "sexually_explicit"}
    all_cats_and_tags = [c.lower() for c in categories] + [t.lower() for t in tags]
    has_adult_signal = any(
        kw in cat_tag or cat_tag in kw
        for cat_tag in all_cats_and_tags
        for kw in _ADULT_KEYWORDS
    )
    content_category = None
    if has_adult_signal:
        content_category = "ADULT_CONTENT"
        if "ADULT_CONTENT_DETECTED" not in behavior_indicators:
            behavior_indicators.append("ADULT_CONTENT_DETECTED")
        reasons.append("Adult content detected by destination classification (unwanted/suspicious content).")

    if engines_v.get("maliciousTotal", 0) > 0:
        is_malicious = True
        malicious_score = max(malicious_score, 80)
        reasons.append(
            f"Security engines in urlscan.io flagged URL as malicious ({engines_v.get('maliciousTotal')} engine detection(s))."
        )

    if is_malicious or malicious_score >= 50 or "phishing" in [c.lower() for c in categories]:
        verdict = "MALICIOUS"
        reasons.append(f"urlscan.io verdict confirms URL is MALICIOUS (score: {malicious_score}/100, categories: {categories}).")
    elif has_adult_signal:
        # Adult content contributes to suspicious/unwanted-content assessment, NOT malware
        verdict = "SUSPICIOUS"
        malicious_score = max(malicious_score, 35)
    elif malicious_score >= 25 or len(downloads) > 0 or ("suspicious" in [t.lower() for t in tags]):
        verdict = "SUSPICIOUS"
        reasons.append(f"urlscan.io sandbox noted SUSPICIOUS behaviors (score: {malicious_score}/100).")
    else:
        verdict = "CLEAN"
        reasons.append(f"urlscan.io dynamic execution completed with no threats detected (score: {malicious_score}/100).")

    return URLScanFinding(
        submitted_url=submitted_url,
        scan_uuid=scan_uuid,
        result_url=result_url,
        screenshot_url=screenshot_url,
        dom_url=dom_url,
        effective_url=effective_url,
        status="COMPLETED",
        verdict=verdict,
        mode="LIVE",
        malicious_score=malicious_score,
        is_malicious=is_malicious,
        content_category=content_category,
        categories=categories,
        tags=tags,
        page_info=page_info,
        redirects=redirect_chain,
        contacted_domains=contacted_domains,
        contacted_ips=contacted_ips,
        downloads=downloads,
        behavior_indicators=behavior_indicators,
        reasons=reasons,
    )


# ═══════════════════════════════════════════════════════════════════
# MOCK / DEMO DATA (Deterministic Offline Provider)
# ═══════════════════════════════════════════════════════════════════

_MOCK_SANDBOX_DB: dict[str, dict[str, Any]] = {
    "http://bit.ly/3xHDFC-verify": {
        "status": "COMPLETED",
        "verdict": "MALICIOUS",
        "malicious_score": 96,
        "is_malicious": True,
        "categories": ["phishing", "credential-harvesting"],
        "tags": ["urlscan-ml", "credential-theft", "fake-bank"],
        "effective_url": "https://secure-banking-update.xyz/login.php",
        "redirects": [
            {"url": "http://bit.ly/3xHDFC-verify", "status": 301, "to": "https://secure-banking-update.xyz/login.php"}
        ],
        "contacted_domains": ["bit.ly", "secure-banking-update.xyz", "evil-cdn.net"],
        "contacted_ips": ["185.234.219.47", "104.21.45.12"],
        "downloads": [
            {
                "url": "https://secure-banking-update.xyz/security_plugin.exe",
                "filename": "security_plugin.exe",
                "mime_type": "application/x-msdownload",
                "size": 524288,
                "hash": "d41d8cd98f00b204e9800998ecf8427e",
            }
        ],
        "behavior_indicators": [
            "Form action targets external unverified domain",
            "Encountered 3 JavaScript console error(s) during sandbox execution.",
            "Sandbox detected web technologies: PHP, Nginx, jQuery",
        ],
        "page_info": {
            "title": "Account Verification Portal",
            "domain": "secure-banking-update.xyz",
            "ip": "185.234.219.47",
            "server": "nginx",
            "status_code": 200,
            "asn_name": "EVIL-HOSTING-AS",
            "tls_issuer": "Let's Encrypt Authority X3",
            "country": "RU",
        },
        "reasons": [
            "Dynamic navigation redirect detected: 'http://bit.ly/3xHDFC-verify' redirected to 'https://secure-banking-update.xyz/login.php'.",
            "urlscan.io verdict confirms URL is MALICIOUS (score: 96/100, categories: ['phishing', 'credential-harvesting']).",
            "URL triggered download of 'security_plugin.exe' (application/x-msdownload).",
        ],
    },
    "https://example.com": {
        "status": "COMPLETED",
        "verdict": "CLEAN",
        "malicious_score": 0,
        "is_malicious": False,
        "categories": [],
        "tags": [],
        "effective_url": "https://example.com/",
        "redirects": [],
        "contacted_domains": ["example.com"],
        "contacted_ips": ["93.184.216.34"],
        "downloads": [],
        "behavior_indicators": [],
        "page_info": {
            "title": "Example Domain",
            "domain": "example.com",
            "ip": "93.184.216.34",
            "server": "ECS",
            "status_code": 200,
            "asn_name": "EDGECAST",
            "tls_issuer": "DigiCert",
            "country": "US",
        },
        "reasons": [
            "urlscan.io dynamic execution completed with no threats detected (score: 0/100)."
        ],
    },
}


def _get_mock_finding(url: str) -> URLScanFinding:
    """Generate a deterministic mock sandbox finding for testing/demo."""
    clean = url.strip()
    # Check exact or prefix match in mock DB
    for k, v in _MOCK_SANDBOX_DB.items():
        if k == clean or k.rstrip("/") == clean.rstrip("/"):
            return URLScanFinding(
                submitted_url=url,
                scan_uuid="mock-scan-uuid-0001",
                result_url=f"https://urlscan.io/result/mock-scan-uuid-0001/",
                screenshot_url="https://urlscan.io/screenshots/mock-scan-uuid-0001.png",
                dom_url="https://urlscan.io/dom/mock-scan-uuid-0001/",
                effective_url=v["effective_url"],
                status=v["status"],
                verdict=v["verdict"],
                mode="MOCK",
                malicious_score=v["malicious_score"],
                is_malicious=v["is_malicious"],
                categories=list(v["categories"]),
                tags=list(v["tags"]),
                page_info=dict(v["page_info"]),
                redirects=list(v["redirects"]),
                contacted_domains=list(v["contacted_domains"]),
                contacted_ips=list(v["contacted_ips"]),
                downloads=list(v["downloads"]),
                behavior_indicators=list(v["behavior_indicators"]),
                reasons=list(v["reasons"]),
            )

    # For any arbitrary URL not explicitly in mock DB:
    # DO NOT return CLEAN! Return UNKNOWN with explicit mock mode.
    domain = urllib.parse.urlparse(url if "://" in url else f"http://{url}").netloc or "example.org"
    return URLScanFinding(
        submitted_url=url,
        scan_uuid="mock-scan-uuid-generic",
        result_url="https://urlscan.io/result/mock-scan-uuid-generic/",
        screenshot_url="https://urlscan.io/screenshots/mock-scan-uuid-generic.png",
        dom_url="https://urlscan.io/dom/mock-scan-uuid-generic/",
        effective_url=url,
        status="COMPLETED",
        verdict="UNKNOWN",
        mode="MOCK",
        malicious_score=0,
        is_malicious=False,
        page_info={
            "title": f"Mock Site - {domain}",
            "domain": domain,
            "ip": "192.0.2.1",
            "server": "DemoServer/1.0",
            "status_code": 200,
            "country": "US",
        },
        contacted_domains=[domain],
        contacted_ips=["192.0.2.1"],
        reasons=["Mock dynamic execution: no deterministic mock record configured for this URL. Submit with force_live=True for live analysis."],
    )


# ═══════════════════════════════════════════════════════════════════
# HIGH-LEVEL RUNNERS
# ═══════════════════════════════════════════════════════════════════

def scan_url_dynamic(
    url: str,
    api_key: Optional[str] = None,
    force_live: bool = False,
    timeout_s: Optional[int] = None,
    poll_interval_s: Optional[float] = None,
) -> URLScanFinding:
    """
    Perform dynamic analysis on a single URL:
    1. If MOCK_URLSCAN is True (and not force_live), returns deterministic mock findings.
    2. Otherwise, submits the URL to the remote urlscan.io sandbox.
    3. Polls for the scan result with timeout handling.
    4. Extracts redirects, contacted network infrastructure, downloads, JS, and page findings.

    Never visits or executes the URL locally.
    """
    mock_mode = getattr(config, "MOCK_URLSCAN", False)
    is_mock = mock_mode and not force_live
    mode = "MOCK" if is_mock else "LIVE"

    logger.info("URL sandbox request initiated: mode=%s, force_live=%s, url=%s", mode, force_live, url)

    if is_mock:
        finding = _get_mock_finding(url)
        logger.info("URL sandbox mock completed: url=%s, status=%s, verdict=%s", url, finding.status, finding.verdict)
        return finding

    key = api_key if api_key is not None else getattr(config, "URLSCAN_API_KEY", "")
    enabled = getattr(config, "URLSCAN_ENABLED", True)
    if not enabled or not key:
        finding = URLScanFinding(
            submitted_url=url,
            status="ERROR",
            verdict="UNKNOWN",
            mode="LIVE",
            reasons=["urlscan.io dynamic analysis is disabled or API key is not configured in .env."],
            error="API key missing or disabled",
        )
        logger.error("URL sandbox error: mode=LIVE, status=ERROR, error=%s, url=%s", finding.error, url)
        return finding

    poll_timeout = timeout_s if timeout_s is not None else getattr(config, "URLSCAN_POLL_TIMEOUT_S", 45)
    poll_interval = poll_interval_s if poll_interval_s is not None else getattr(config, "URLSCAN_POLL_INTERVAL_S", 3.0)
    visibility = getattr(config, "URLSCAN_VISIBILITY", "unlisted")

    # Step 1: Submit to remote sandbox
    scan_uuid, result_url, submit_err = submit_scan(
        url=url,
        api_key=key,
        visibility=visibility,
    )

    if submit_err or not scan_uuid:
        finding = URLScanFinding(
            submitted_url=url,
            status="ERROR",
            verdict="UNKNOWN",
            mode="LIVE",
            reasons=[f"Sandbox submission failed: {submit_err}"],
            error=submit_err,
        )
        logger.error("URL sandbox submission failed: mode=LIVE, status=ERROR, error=%s, url=%s", submit_err, url)
        return finding

    # Step 2: Poll for scan result
    result_data, poll_err = poll_scan_result(
        uuid=scan_uuid,
        api_key=key,
        max_wait_s=poll_timeout,
        poll_interval_s=poll_interval,
    )

    if poll_err or not result_data:
        is_timeout = "timed out" in (poll_err or "").lower()
        status_code = "TIMEOUT" if is_timeout else "ERROR"
        finding = URLScanFinding(
            submitted_url=url,
            scan_uuid=scan_uuid,
            result_url=result_url or f"https://urlscan.io/result/{scan_uuid}/",
            screenshot_url=f"https://urlscan.io/screenshots/{scan_uuid}.png",
            status=status_code,
            verdict="UNKNOWN",
            mode="LIVE",
            reasons=[f"urlscan.io analysis did not complete: {poll_err}"],
            error=poll_err,
        )
        logger.error("URL sandbox polling failed: mode=LIVE, status=%s, error=%s, url=%s", status_code, poll_err, url)
        return finding

    # Step 3: Extract structured findings
    finding = extract_sandbox_findings(
        submitted_url=url,
        scan_uuid=scan_uuid,
        data=result_data,
    )
    finding.mode = "LIVE"
    logger.info("URL sandbox live scan completed: mode=LIVE, status=%s, verdict=%s, score=%d, url=%s",
                finding.status, finding.verdict, finding.malicious_score, url)
    return finding


def analyze_urls_dynamic(
    urls: list[str],
    max_scans: Optional[int] = None,
    api_key: Optional[str] = None,
    force_live: bool = False,
) -> URLSandboxAnalysis:
    """
    Batch runner for email pipeline integration:
    Deduplicates URLs, filters down to max_scans (to respect API limits),
    submits them to the sandbox, and returns an aggregated URLSandboxAnalysis.
    """
    limitations: list[str] = [
        "Dynamic analysis executes in an isolated remote urlscan.io browser sandbox.",
        "URLs are never opened, rendered, or executed on the local server.",
    ]

    mock_mode = getattr(config, "MOCK_URLSCAN", False)
    is_mock = mock_mode and not force_live
    mode = "MOCK" if is_mock else "LIVE"

    key = api_key if api_key is not None else getattr(config, "URLSCAN_API_KEY", "")
    enabled = getattr(config, "URLSCAN_ENABLED", True)

    if not is_mock and (not enabled or not key):
        limitations.append("urlscan.io API key not configured or feature disabled; dynamic analysis skipped.")
        return URLSandboxAnalysis(
            total_scanned=0,
            malicious_count=0,
            suspicious_count=0,
            mode=mode,
            findings=[],
            source="urlscan.io Dynamic Sandbox (Disabled)",
            limitations=limitations,
        )

    # Deduplicate while preserving order
    unique_urls: list[str] = []
    seen: set[str] = set()
    for u in urls:
        clean = (u or "").strip().rstrip(".,;:)'\"")
        if clean and clean.lower() not in seen:
            seen.add(clean.lower())
            unique_urls.append(clean)

    limit = max_scans if max_scans is not None else getattr(config, "URLSCAN_MAX_URLS_PER_ANALYSIS", 3)
    target_urls = unique_urls[:limit]

    if len(unique_urls) > limit:
        limitations.append(
            f"Only the first {limit} unique URLs were dynamically scanned to preserve API quotas."
        )

    findings: list[URLScanFinding] = []
    for u in target_urls:
        finding = scan_url_dynamic(u, api_key=key, force_live=force_live)
        findings.append(finding)

    malicious_count = sum(1 for f in findings if f.is_malicious or f.verdict == "MALICIOUS")
    suspicious_count = sum(1 for f in findings if f.verdict == "SUSPICIOUS")

    return URLSandboxAnalysis(
        total_scanned=len(findings),
        malicious_count=malicious_count,
        suspicious_count=suspicious_count,
        mode=mode,
        findings=findings,
        source="urlscan.io Dynamic Sandbox (Mock/Demo)" if is_mock else "urlscan.io Dynamic Sandbox",
        limitations=limitations,
    )


# ═══════════════════════════════════════════════════════════════════
# STANDALONE CLI TEST RUNNER
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    test_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print("\n" + "=" * 65)
    print(f"  GmailGuard — URL Dynamic Analysis Sandbox (urlscan.io)")
    print("=" * 65)
    print(f"  Target URL       : {test_url}")
    print(f"  Execution Env    : Remote urlscan.io Sandbox (Zero Local Execution)")
    print(f"  API Key Status   : {'Configured' if getattr(config, 'URLSCAN_API_KEY', '') else 'Missing'}")
    print("-" * 65)
    print("  Submitting URL to urlscan.io and polling result (live)...")

    finding = scan_url_dynamic(test_url, force_live=True)

    print("\n" + "=" * 65)
    print("  URL DYNAMIC ANALYSIS FINDINGS")
    print("=" * 65)
    print(f"  Status           : {finding.status}")
    print(f"  Verdict          : {finding.verdict} (Malicious Score: {finding.malicious_score}/100)")
    print(f"  Scan UUID        : {finding.scan_uuid}")
    print(f"  Report URL       : {finding.result_url}")
    print(f"  Screenshot URL   : {finding.screenshot_url}")
    print(f"  Effective URL    : {finding.effective_url}")
    print(f"  Page Title       : {finding.page_info.get('title', 'N/A')}")
    print(f"  Server / Status  : {finding.page_info.get('server', 'N/A')} (HTTP {finding.page_info.get('status_code', 'N/A')})")
    print(f"  Resolved IP/ASN  : {finding.page_info.get('ip', 'N/A')} / {finding.page_info.get('asn_name', 'N/A')}")
    print(f"  Contacted Domains: {', '.join(finding.contacted_domains[:5]) or 'None'}")
    print(f"  Contacted IPs    : {', '.join(finding.contacted_ips[:5]) or 'None'}")
    print(f"  Downloads Found  : {len(finding.downloads)}")
    for dl in finding.downloads:
        print(f"    - {dl.get('filename')} ({dl.get('mime_type')}) [{dl.get('size')} bytes]")
    print(f"  Behavior Signs   : {len(finding.behavior_indicators)}")
    for b in finding.behavior_indicators:
        print(f"    - {b}")
    print(f"  Forensic Reasons : {len(finding.reasons)}")
    for r in finding.reasons:
        print(f"    - {r}")
    if finding.error:
        print(f"  Error / Warning  : {finding.error}")
    print("=" * 65 + "\n")
