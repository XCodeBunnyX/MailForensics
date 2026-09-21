"""
GmailGuard — Gemini AI Analysis Service

Provides contextual email security reasoning and explanation using Google GenAI SDK.
Analyzes email content, headers, extracted indicators, and correlates with
existing forensic threat results to provide a structured, human-readable assessment.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Optional

from dotenv import load_dotenv

logger = logging.getLogger("gmailguard.gemini")

# Candidate models in order of priority (using fast, reliable Google GenAI flash models)
_CANDIDATE_MODELS = [
    os.getenv("GEMINI_MODEL", "gemini-3.5-flash"),
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-flash-latest",
]


def _get_api_key() -> str:
    """Safely fetch GEMINI_API_KEY from environment without caching stale values."""
    load_dotenv(override=False)
    return os.getenv("GEMINI_API_KEY", "").strip()


def is_gemini_available() -> bool:
    """Check if Gemini API key and dependencies are available."""
    if not _get_api_key():
        return False
    try:
        import google.genai  # noqa: F401
        return True
    except ImportError:
        return False


def _sanitize_text(text: str, max_chars: int = 12000) -> str:
    """Trim text to fit comfortably within model prompt limits while preserving critical context."""
    if not text:
        return ""
    text = text.strip()
    if len(text) > max_chars:
        return text[:max_chars] + f"\n... [Truncated: content exceeded {max_chars} characters]"
    return text


def build_email_analysis_payload(
    raw_email: Optional[str] = None,
    report: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Extract relevant, safe security attributes for Gemini analysis.
    Never includes credentials, passwords, session tokens, or API keys.
    """
    report = report or {}
    email_meta = report.get("email", {})
    auth = report.get("authentication", {})
    infra = report.get("infrastructure", {})
    urls_data = report.get("urls", {})
    attachments_data = report.get("attachments", {})
    domain_data = report.get("domain", {})
    ml_data = report.get("ml", {})
    evidence_list = report.get("evidence", [])

    # Extract clean text body from raw_email if email_parser is available
    text_body = ""
    html_snippet = ""
    if raw_email:
        try:
            try:
                from .email_parser import parse_email
            except ImportError:
                from email_parser import parse_email
            parsed = parse_email(raw_email)
            text_body = parsed.text_body or ""
            if not text_body and parsed.html_body:
                # Basic strip of HTML tags for readable text
                text_body = re.sub(r"<[^>]+>", " ", parsed.html_body)
                text_body = re.sub(r"\s+", " ", text_body)
            html_snippet = parsed.html_body[:3000] if parsed.html_body else ""
        except Exception as e:
            logger.debug("Failed to extract body via email_parser: %s", e)

    # Collect URLs
    extracted_urls = []
    if isinstance(urls_data.get("findings"), list):
        for u in urls_data["findings"][:15]:
            if isinstance(u, dict) and u.get("url"):
                extracted_urls.append({
                    "url": u.get("url"),
                    "domain": u.get("domain"),
                    "suspicious": u.get("is_suspicious", False),
                    "reasons": u.get("suspicious_reasons", []),
                })

    # Collect Attachments
    extracted_attachments = []
    if isinstance(attachments_data.get("findings"), list):
        for att in attachments_data["findings"][:10]:
            if isinstance(att, dict):
                extracted_attachments.append({
                    "filename": att.get("filename"),
                    "file_type": att.get("file_type"),
                    "is_dangerous": att.get("is_dangerous", False),
                })

    return {
        "sender": email_meta.get("from", ""),
        "sender_email": email_meta.get("sender_email", ""),
        "sender_name": email_meta.get("sender_name", ""),
        "sender_domain": email_meta.get("sender_domain", "") or domain_data.get("domain", ""),
        "reply_to": email_meta.get("reply_to", ""),
        "recipient": email_meta.get("to", ""),
        "subject": email_meta.get("subject", ""),
        "date": email_meta.get("date", ""),
        "email_body_text": _sanitize_text(text_body),
        "email_html_snippet": _sanitize_text(html_snippet, max_chars=2500),
        "authentication": {
            "spf": auth.get("spf", "NONE"),
            "dkim": auth.get("dkim", "NONE"),
            "dmarc": auth.get("dmarc", "NONE"),
            "summary": auth.get("summary", ""),
        },
        "infrastructure": {
            "candidate_ips": infra.get("public_ips", [])[:5],
            "reply_to_differs": infra.get("reply_to_differs", False),
        },
        "extracted_urls": extracted_urls,
        "attachments": extracted_attachments,
        "static_ml_prediction": ml_data.get("prediction", "UNKNOWN"),
        "threat_score": report.get("threat_score"),
        "verdict": report.get("verdict"),
        "forensic_evidence_signals": [
            ev.get("explanation") for ev in evidence_list[:8] if isinstance(ev, dict) and ev.get("explanation")
        ],
    }


def _build_system_prompt() -> str:
    return """You are a Principal Email Forensics and Cybersecurity Intelligence Analyst.
Your role is to perform contextual, evidence-based security reasoning on incoming emails.

Guidelines:
1. Distinguish carefully between:
   - "phishing" (deliberate credential harvesting, deceptive links, or social engineering)
   - "suspicious" (anomalous headers, brand inconsistencies, or suspicious sender behavior without definitive malicious payload)
   - "benign" (legitimate transactional, personal, or corporate communication)
   - "insufficient_evidence" (cannot determine with confidence)
2. Risk levels must be one of: "critical", "high", "medium", "low", "none".
3. Evaluate specific indicators:
   - Social engineering (urgency, coercion, fear, authority, unexpected invoices/prizes)
   - Brand impersonation (typosquatting, lookalike domains, sender display name vs actual address)
   - Sender authentication mismatches (SPF/DKIM/DMARC failures or reply-to discrepancy)
   - Dangerous links or domain deception (URL anchor text vs target destination)
   - Suspicious attachments or executable extensions
4. Do NOT hallucinate threats where none exist; if an email is a standard automated notification or newsletter with passing authentication, classify it as benign.
5. Provide actionable recommendations for the SOC analyst or end-user.

You MUST respond strictly with valid JSON conforming to the following structure:
{
  "classification": "phishing" | "suspicious" | "benign" | "insufficient_evidence",
  "risk_level": "critical" | "high" | "medium" | "low" | "none",
  "confidence": <integer between 0 and 100>,
  "summary": "<1-2 sentence executive summary of the assessment>",
  "threat_indicators": [
    {
      "indicator": "<short title of indicator>",
      "evidence": "<concrete evidence from the email or headers>",
      "severity": "high" | "medium" | "low"
    }
  ],
  "social_engineering_indicators": [
    "<specific psychological tactic, urgency trigger, or deception pattern>"
  ],
  "suspicious_urls": [
    "<url or domain identified as deceptive or suspicious>"
  ],
  "suspicious_domains": [
    "<domain identified as impersonating or deceptive>"
  ],
  "recommended_actions": [
    "<specific remediation or defense recommendation>"
  ],
  "explanation": "<detailed multi-paragraph rationale explaining why this verdict was reached based on the technical and linguistic evidence>"
}
"""


def _clean_json_text(text: str) -> str:
    """Strip markdown code fences and whitespace from Gemini response."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Remove first line (e.g. ```json)
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        # Remove last line if ```
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _extract_fields_via_regex(text: str) -> dict[str, Any]:
    """Extract individual JSON fields using regex when full JSON decoding fails."""
    data: dict[str, Any] = {}

    m_cls = re.search(r'"classification"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
    if m_cls:
        data["classification"] = m_cls.group(1).lower()

    m_risk = re.search(r'"risk_level"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
    if m_risk:
        data["risk_level"] = m_risk.group(1).lower()

    m_conf = re.search(r'"confidence"\s*:\s*(\d+)', text)
    if m_conf:
        data["confidence"] = int(m_conf.group(1))

    m_sum = re.search(r'"summary"\s*:\s*"((?:[^"\\]|\\.)*)"', text, re.DOTALL)
    if m_sum:
        data["summary"] = m_sum.group(1).replace("\\n", "\n").replace('\\"', '"')

    m_exp = re.search(r'"explanation"\s*:\s*"((?:[^"\\]|\\.)*)"', text, re.DOTALL)
    if m_exp:
        data["explanation"] = m_exp.group(1).replace("\\n", "\n").replace('\\"', '"')

    return data


def run_gemini_analysis(
    raw_email: Optional[str] = None,
    report: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Run Gemini AI analysis on email context and combine with forensic results.
    Never throws an exception that crashes the host pipeline.
    """
    api_key = _get_api_key()
    if not api_key:
        logger.info("GEMINI_API_KEY not configured. Skipping Gemini AI analysis.")
        return {
            "available": False,
            "reason": "GEMINI_API_KEY is not configured in backend environment.",
            "classification": "unavailable",
            "risk_level": "none",
            "confidence": 0,
            "summary": "Gemini AI analysis is unconfigured.",
            "threat_indicators": [],
            "social_engineering_indicators": [],
            "suspicious_urls": [],
            "suspicious_domains": [],
            "recommended_actions": [],
            "explanation": "Configure GEMINI_API_KEY in backend/.env to enable contextual AI email threat reasoning.",
        }

    try:
        from google import genai
        from google.genai import types
    except ImportError:
        logger.warning("google-genai SDK is not installed in the environment.")
        return {
            "available": False,
            "reason": "google-genai package is not installed.",
            "classification": "unavailable",
            "risk_level": "none",
            "confidence": 0,
            "summary": "google-genai SDK not installed.",
            "threat_indicators": [],
            "social_engineering_indicators": [],
            "suspicious_urls": [],
            "suspicious_domains": [],
            "recommended_actions": [],
            "explanation": "Please install google-genai to enable AI analysis.",
        }

    # Extract structured email info
    payload = build_email_analysis_payload(raw_email=raw_email, report=report)

    prompt = (
        f"{_build_system_prompt()}\n\n"
        f"EMAIL FORENSIC EVIDENCE AND CONTENT FOR ANALYSIS:\n"
        f"```json\n{json.dumps(payload, indent=2)}\n```\n\n"
        f"Analyze the email above and produce the requested JSON output."
    )

    try:
        client = genai.Client(api_key=api_key)
        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1,
        )
    except Exception as init_err:
        logger.error("Failed to initialize Google GenAI client: %s", init_err)
        return {
            "available": False,
            "reason": f"Client initialization error: {init_err}",
            "classification": "unavailable",
            "risk_level": "unknown",
            "confidence": 0,
            "summary": "Google GenAI client could not be initialized.",
            "threat_indicators": [],
            "social_engineering_indicators": [],
            "suspicious_urls": [],
            "suspicious_domains": [],
            "recommended_actions": [],
            "explanation": f"Google GenAI initialization failed: {init_err}",
        }

    last_error: Optional[Exception] = None
    response_text = ""
    successful_model: Optional[str] = None

    # Attempt candidate models in priority order
    for model_name in _CANDIDATE_MODELS:
        try:
            logger.info("Invoking Gemini model '%s' for email analysis...", model_name)
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=config,
            )
            if response and response.text:
                response_text = response.text
                successful_model = model_name
                break
        except Exception as err:
            logger.warning("Gemini model '%s' invocation failed: %s", model_name, err)
            last_error = err

    if not response_text:
        err_msg = str(last_error) if last_error else "Empty response from Gemini models"
        logger.error("All Gemini candidate models failed: %s", err_msg)
        return {
            "available": False,
            "reason": f"AI analysis service error: {err_msg}",
            "classification": "unavailable",
            "risk_level": "unknown",
            "confidence": 0,
            "summary": "Gemini AI analysis could not be completed at this time.",
            "threat_indicators": [],
            "social_engineering_indicators": [],
            "suspicious_urls": [],
            "suspicious_domains": [],
            "recommended_actions": [],
            "explanation": "The AI analysis service was temporarily unreachable or returned an error.",
        }

    # Parse JSON safely with multi-layer resilience
    parsed_result = {}
    cleaned_json = _clean_json_text(response_text)

    try:
        parsed_result = json.loads(cleaned_json)
    except Exception:
        try:
            # Handles unescaped control characters/newlines inside string fields
            parsed_result = json.loads(cleaned_json, strict=False)
        except Exception as parse_err:
            logger.warning("Standard JSON parse failed, extracting fields with regex: %s", parse_err)
            parsed_result = _extract_fields_via_regex(response_text)

    # Normalize fields to guarantee contract stability
    return {
        "available": True,
        "classification": str(parsed_result.get("classification", "insufficient_evidence")).lower(),
        "risk_level": str(parsed_result.get("risk_level", "low")).lower(),
        "confidence": int(parsed_result.get("confidence", 0)),
        "summary": str(parsed_result.get("summary", "")),
        "threat_indicators": list(parsed_result.get("threat_indicators", [])),
        "social_engineering_indicators": list(parsed_result.get("social_engineering_indicators", [])),
        "suspicious_urls": list(parsed_result.get("suspicious_urls", [])),
        "suspicious_domains": list(parsed_result.get("suspicious_domains", [])),
        "recommended_actions": list(parsed_result.get("recommended_actions", [])),
        "explanation": str(parsed_result.get("explanation", "")),
        "model_used": successful_model or "gemini-flash-latest",
    }
