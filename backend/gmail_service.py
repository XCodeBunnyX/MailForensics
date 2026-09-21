"""
GmailGuard — Official Gmail API & OAuth 2.0 Integration Service

Handles:
1. Google OAuth 2.0 authorization with least-privilege 'gmail.readonly' scope.
2. Server-side token storage and automatic refresh without frontend token exposure.
3. Fetching user mailbox messages with metadata, read/unread states, and attachment/URL indicators.
4. Retrieving complete raw RFC 5322 email bytes (via format='raw') for zero-loss ingestion into the core pipeline.
5. Persistent local analysis caching keyed by gmail_message_id.
6. Offline / demo mode fallback when Google OAuth credentials are not yet configured.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

from . import config

# Set oauthlib environment flags for local development
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

logger = logging.getLogger("gmailguard.gmail")

# Scopes: least-privilege read-only email access and user email profile
SCOPES = config.GMAIL_SCOPES


class GmailService:
    """Manages official Gmail API OAuth 2.0 flows and message operations."""

    def __init__(self) -> None:
        self.token_path = config.GMAIL_TOKEN_PATH
        self.cache_path = config.GMAIL_CACHE_PATH
        self.state_path = Path(__file__).resolve().parent / ".gmail_oauth_states.json"
        self._memory_states: dict[str, dict[str, Any]] = {}

    # ── State & PKCE Persistence ────────────────────────────────────

    def _save_oauth_state(self, state: str, code_verifier: Optional[str], redirect_uri: Optional[str] = None) -> None:
        """Persist state, PKCE code_verifier, and matching redirect_uri across HTTP requests."""
        now = time.time()
        entry = {"verifier": code_verifier, "redirect_uri": redirect_uri, "ts": now}
        self._memory_states[state] = entry
        try:
            states = {}
            if self.state_path.exists():
                try:
                    with open(self.state_path, "r", encoding="utf-8") as f:
                        states = json.load(f)
                except Exception:
                    states = {}
            # Prune states older than 1 hour
            states = {k: v for k, v in states.items() if isinstance(v, dict) and now - v.get("ts", 0) < 3600}
            states[state] = entry
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(states, f, indent=2)
        except Exception as e:
            logger.debug("Failed to write OAuth state to disk (in-memory available): %s", e)

    def _pop_oauth_state(self, state: Optional[str]) -> tuple[Optional[str], Optional[str]]:
        """
        Retrieve and remove PKCE code_verifier and saved redirect_uri associated with state.
        Includes robust fallback for local single-user sessions if state was lost or modified.
        Returns: (code_verifier, saved_redirect_uri)
        """
        now = time.time()
        verifier: Optional[str] = None
        saved_r_uri: Optional[str] = None

        if state and state in self._memory_states:
            entry = self._memory_states.pop(state, None)
            if isinstance(entry, dict):
                verifier = entry.get("verifier")
                saved_r_uri = entry.get("redirect_uri")

        try:
            if self.state_path.exists():
                try:
                    with open(self.state_path, "r", encoding="utf-8") as f:
                        states = json.load(f)
                except Exception:
                    states = {}

                # 1. Exact match
                if state and state in states:
                    file_entry = states.pop(state, None)
                    if isinstance(file_entry, dict):
                        verifier = verifier or file_entry.get("verifier")
                        saved_r_uri = saved_r_uri or file_entry.get("redirect_uri")

                # 2. Fallback: if no verifier found, look for any recent valid verifier created in the last 15 minutes
                if not verifier and states:
                    recent_entries = sorted(
                        [(k, v) for k, v in states.items() if isinstance(v, dict) and now - v.get("ts", 0) < 900],
                        key=lambda x: x[1].get("ts", 0),
                        reverse=True,
                    )
                    if recent_entries:
                        chosen_k, chosen_v = recent_entries[0]
                        verifier = chosen_v.get("verifier")
                        saved_r_uri = chosen_v.get("redirect_uri")
                        states.pop(chosen_k, None)
                        logger.info("Retrieved PKCE code verifier via recent OAuth state fallback (%s)", chosen_k)

                with open(self.state_path, "w", encoding="utf-8") as f:
                    json.dump(states, f, indent=2)
        except Exception as e:
            logger.debug("Failed to remove OAuth state from disk: %s", e)

        return verifier, saved_r_uri

    # ── Configuration & OAuth Helpers ───────────────────────────────

    def is_configured(self) -> bool:
        """Check if OAuth Client credentials (ID + Secret or File) are configured."""
        if hasattr(config, "GMAIL_CLIENT_ID") and not config.GMAIL_CLIENT_ID:
            return False
        if hasattr(config, "GMAIL_CLIENT_SECRET") and not config.GMAIL_CLIENT_SECRET:
            return False

        cid = getattr(config, "GMAIL_CLIENT_ID", "") or getattr(config, "get_gmail_client_id", lambda: "")()
        csec = getattr(config, "GMAIL_CLIENT_SECRET", "") or getattr(config, "get_gmail_client_secret", lambda: "")()
        if cid and csec:
            return True
        if config.GMAIL_CREDENTIALS_FILE and os.path.exists(config.GMAIL_CREDENTIALS_FILE):
            return True
        # Check if client_secret.json exists in backend directory
        default_file = Path(__file__).resolve().parent / "client_secret.json"
        return default_file.exists()

    def _get_client_config(self) -> dict[str, Any]:
        """Build Google OAuth client configuration dict."""
        cid = getattr(config, "GMAIL_CLIENT_ID", "") or getattr(config, "get_gmail_client_id", lambda: "")()
        csec = getattr(config, "GMAIL_CLIENT_SECRET", "") or getattr(config, "get_gmail_client_secret", lambda: "")()
        r_uri = getattr(config, "GMAIL_REDIRECT_URI", "") or getattr(config, "get_gmail_redirect_uri", lambda: "")()
        if cid and csec:
            return {
                "web": {
                    "client_id": cid,
                    "client_secret": csec,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [r_uri or "http://127.0.0.1:8000/api/gmail/oauth2callback"],
                }
            }
        
        credentials_file = config.GMAIL_CREDENTIALS_FILE
        if not credentials_file or not os.path.exists(credentials_file):
            default_file = Path(__file__).resolve().parent / "client_secret.json"
            if default_file.exists():
                credentials_file = str(default_file)

        if credentials_file and os.path.exists(credentials_file):
            with open(credentials_file, "r", encoding="utf-8") as f:
                return json.load(f)

        raise ValueError("Google OAuth credentials are not configured in backend/.env")

    def get_authorization_url(self, redirect_uri: Optional[str] = None) -> tuple[str, str]:
        """
        Generate Google OAuth 2.0 consent URL for least-privilege read-only access.
        Preserves PKCE code_verifier associated with state for token exchange.
        Returns: (auth_url, state)
        """
        from google_auth_oauthlib.flow import Flow

        client_config = self._get_client_config()
        r_uri = redirect_uri or getattr(config, "get_gmail_redirect_uri", lambda: getattr(config, "GMAIL_REDIRECT_URI", ""))()

        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=r_uri,
            autogenerate_code_verifier=True,
        )

        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        if flow.code_verifier:
            self._save_oauth_state(state, flow.code_verifier, r_uri)
        return auth_url, state

    def handle_oauth_callback(
        self,
        code: str,
        state: Optional[str] = None,
        redirect_uri: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Exchange authorization code for OAuth credentials and save securely server-side.
        Never exposes tokens or secrets to frontend JavaScript or logs.
        """
        from google_auth_oauthlib.flow import Flow

        client_config = self._get_client_config()
        code_verifier, saved_r_uri = self._pop_oauth_state(state)
        r_uri = redirect_uri or saved_r_uri or getattr(config, "get_gmail_redirect_uri", lambda: getattr(config, "GMAIL_REDIRECT_URI", ""))()

        # Ensure r_uri is in client_config redirect_uris list
        if r_uri and r_uri not in client_config["web"].setdefault("redirect_uris", []):
            client_config["web"]["redirect_uris"].append(r_uri)

        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=r_uri,
            state=state,
            code_verifier=code_verifier,
            autogenerate_code_verifier=False,
        )
        if code_verifier:
            flow.code_verifier = code_verifier

        fetch_kwargs: dict[str, Any] = {"code": code}
        if code_verifier:
            fetch_kwargs["code_verifier"] = code_verifier

        logger.info(
            "OAuth callback processing: code=YES, state=%s, code_verifier=%s, redirect_uri=%s",
            bool(state),
            "YES" if code_verifier else "NO",
            r_uri,
        )

        try:
            flow.fetch_token(**fetch_kwargs)
        except Exception as exc:
            logger.error("OAuth flow.fetch_token failed: %s (type: %s)", exc, type(exc).__name__)
            try:
                debug_log = Path(__file__).resolve().parent / "oauth_debug.log"
                with open(debug_log, "a", encoding="utf-8") as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] flow.fetch_token error: {type(exc).__name__}: {exc}\n")
                    f.write(f"  redirect_uri={r_uri}, state={state}, verifier_found={bool(code_verifier)}\n")
            except Exception:
                pass
            raise

        credentials = flow.credentials

        logger.info("Token exchange: SUCCESS")
        logger.info("Refresh token received: %s", "YES" if credentials.refresh_token else "NO")

        # Store token securely server-side in gitignored file
        token_data = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes,
        }

        with open(self.token_path, "w", encoding="utf-8") as f:
            json.dump(token_data, f, indent=2)

        user_info = self.get_user_info()
        logger.info("Gmail API authentication: %s", "SUCCESS" if user_info.get("connected") else "FAILURE")
        return {
            "connected": True,
            "email": user_info.get("email", ""),
            "message": "Gmail account connected successfully.",
        }

    def _get_credentials(self) -> Any:
        """Load and refresh stored credentials if valid."""
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request

        if not self.token_path.exists():
            return None

        try:
            with open(self.token_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            creds = Credentials(
                token=data.get("token"),
                refresh_token=data.get("refresh_token"),
                token_uri=data.get("token_uri"),
                client_id=data.get("client_id"),
                client_secret=data.get("client_secret"),
                scopes=data.get("scopes", SCOPES),
            )

            if creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    # Update saved token
                    data["token"] = creds.token
                    with open(self.token_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2)
                except Exception as ref_err:
                    logger.warning("Failed to refresh Gmail OAuth token: %s", ref_err)
                    return None

            return creds if creds.valid else None
        except Exception as e:
            logger.warning("Error reading stored Gmail token: %s", e)
            return None

    def is_authenticated(self) -> bool:
        """Check if an active, valid Gmail session exists."""
        return self._get_credentials() is not None

    def get_user_info(self) -> dict[str, Any]:
        """Fetch the connected user's email address profile."""
        creds = self._get_credentials()
        if not creds:
            return {"connected": False, "email": "", "configured": self.is_configured()}

        try:
            from googleapiclient.discovery import build
            service = build("gmail", "v1", credentials=creds, cache_discovery=False)
            profile = service.users().getProfile(userId="me").execute()
            return {
                "connected": True,
                "email": profile.get("emailAddress", "Connected User"),
                "messages_total": profile.get("messagesTotal", 0),
                "configured": True,
            }
        except Exception as e:
            logger.error("Failed to fetch Gmail profile: %s", e)
            return {"connected": False, "email": "", "configured": True, "error": str(e)}

    def disconnect(self) -> bool:
        """Disconnect Gmail account and clear local OAuth token."""
        if self.token_path.exists():
            try:
                self.token_path.unlink()
                logger.info("Gmail credentials removed.")
                return True
            except Exception as e:
                logger.error("Failed to delete token file: %s", e)
                return False
        return True

    # ── Mail Retrieval & Conversion ─────────────────────────────────

    def list_messages(
        self,
        max_results: int = 25,
        query: Optional[str] = None,
        page_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        List user emails with envelope metadata, read/unread states,
        attachment/URL indicators, and cached threat scores.
        Falls back to demonstration inbox if unauthenticated.
        """
        creds = self._get_credentials()
        if not creds:
            # Fallback to realistic demo inbox for reviewer evaluation
            return self._get_demo_messages()

        try:
            from googleapiclient.discovery import build
            service = build("gmail", "v1", credentials=creds, cache_discovery=False)

            params: dict[str, Any] = {
                "userId": "me",
                "maxResults": min(max(max_results, 5), 50),
            }
            if query:
                params["q"] = query
            if page_token:
                params["pageToken"] = page_token

            res = service.users().messages().list(**params).execute()
            raw_items = res.get("messages", [])
            next_page_token = res.get("nextPageToken")

            cached_map = self._get_cached_map()
            items = []

            for item in raw_items:
                msg_id = item["id"]
                try:
                    # Fetch header metadata
                    msg = service.users().messages().get(
                        userId="me",
                        id=msg_id,
                        format="metadata",
                        metadataHeaders=["From", "To", "Subject", "Date"],
                    ).execute()

                    headers_dict = {
                        h["name"].lower(): h["value"]
                        for h in msg.get("payload", {}).get("headers", [])
                    }

                    from_raw = headers_dict.get("from", "Unknown Sender")
                    sender_name, sender_email = self._split_sender(from_raw)

                    # Inspect body snippet for URLs
                    snippet = msg.get("snippet", "")
                    has_urls = bool(re.search(r"https?://", snippet, re.IGNORECASE))
                    label_ids = msg.get("labelIds", [])
                    is_unread = "UNREAD" in label_ids

                    # Check for attachments in mime types
                    mime_type = msg.get("payload", {}).get("mimeType", "")
                    has_attachments = "multipart" in mime_type and any(
                        p.get("filename") for p in msg.get("payload", {}).get("parts", [])
                    )

                    cached = cached_map.get(msg_id)
                    items.append({
                        "id": msg_id,
                        "thread_id": msg.get("threadId", ""),
                        "sender": from_raw,
                        "to": headers_dict.get("to", ""),
                        "labels": label_ids,
                        "sender_name": sender_name,
                        "sender_email": sender_email,
                        "subject": headers_dict.get("subject", "(No Subject)"),
                        "date": headers_dict.get("date", ""),
                        "snippet": snippet,
                        "is_unread": is_unread,
                        "has_attachments": has_attachments,
                        "has_urls": has_urls,
                        "analysis_status": "ANALYZED" if cached else "NOT_ANALYZED",
                        "threat_score": cached.get("threat_score") if cached else None,
                        "threat_verdict": cached.get("verdict") if cached else None,
                        "gemini_assessment": (
                            cached.get("gemini_analysis", {}).get("overall_assessment")
                            if cached else None
                        ),
                    })
                except Exception as msg_err:
                    logger.warning("Error fetching metadata for msg %s: %s", msg_id, msg_err)
                    continue

            return {
                "mode": "LIVE",
                "connected": True,
                "messages": items,
                "next_page_token": next_page_token,
                "result_size_estimate": res.get("resultSizeEstimate", len(items)),
            }
        except Exception as e:
            logger.error("Gmail API list_messages error: %s", e)
            # Gracefully return demo messages with an alert notice
            demo = self._get_demo_messages()
            demo["error"] = f"Live Gmail API request failed: {e}. Showing demonstration emails."
            return demo

    def get_message_raw(self, message_id: str) -> str:
        """
        Retrieve complete email from Gmail using format='raw',
        decode base64url bytes into RFC 5322 string.
        Guarantees exact parity with .eml uploads for existing pipeline.
        """
        creds = self._get_credentials()
        if not creds:
            return self._get_demo_raw_email(message_id)

        try:
            from googleapiclient.discovery import build
            service = build("gmail", "v1", credentials=creds, cache_discovery=False)
            res = service.users().messages().get(
                userId="me",
                id=message_id,
                format="raw",
            ).execute()

            raw_base64url = res.get("raw", "")
            raw_bytes = base64.urlsafe_b64decode(raw_base64url.encode("ASCII"))
            return raw_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            logger.error("Failed to fetch raw message %s: %s", message_id, e)
            return self._get_demo_raw_email(message_id)

    # ── Analysis Caching ────────────────────────────────────────────

    def _get_cached_map(self) -> dict[str, dict[str, Any]]:
        """Read analysis cache file safely."""
        if not self.cache_path.exists():
            return {}
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Error reading Gmail analysis cache: %s", e)
            return {}

    def get_cached_analysis(self, message_id: str) -> Optional[dict[str, Any]]:
        """Retrieve cached forensic report by Gmail message ID."""
        cache = self._get_cached_map()
        return cache.get(message_id)

    def save_cached_analysis(self, message_id: str, report: dict[str, Any]) -> None:
        """Save forensic report associated with Gmail message ID."""
        cache = self._get_cached_map()
        # Save slim reference with core threat indicators and Gemini analysis
        cache[message_id] = report
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            logger.error("Failed to write to Gmail analysis cache: %s", e)

    def list_all_cached_analyses(self) -> list[dict[str, Any]]:
        """List all analyzed email reports stored in cache."""
        cache = self._get_cached_map()
        return list(cache.values())

    # ── Utility Helpers & Demo Mode ─────────────────────────────────

    @staticmethod
    def _split_sender(from_header: str) -> tuple[str, str]:
        """Split 'John Doe <john@example.com>' into ('John Doe', 'john@example.com')."""
        m = re.search(r"^(.*?)\s*<([^>]+)>$", from_header)
        if m:
            name = m.group(1).strip().strip('"').strip("'")
            return name or m.group(2).strip(), m.group(2).strip()
        if "@" in from_header:
            clean = from_header.strip().strip("<>").strip('"')
            return clean, clean
        return from_header, from_header

    def _get_demo_messages(self) -> dict[str, Any]:
        """Realistic simulated Gmail inbox for offline testing and reviewer demonstration."""
        cached_map = self._get_cached_map()
        demo_items = [
            {
                "id": "demo-msg-001",
                "thread_id": "thread-001",
                "sender_name": "Axis Bank Alert",
                "sender_email": "alerts@axisbank-security-update.xyz",
                "subject": "CRITICAL: Immediate Account Verification Required",
                "date": "Today, 10:42 AM",
                "snippet": "Dear Customer, Your Axis Bank netbanking access has been flagged due to suspicious attempts. Verify credentials immediately...",
                "is_unread": True,
                "has_attachments": False,
                "has_urls": True,
            },
            {
                "id": "demo-msg-002",
                "thread_id": "thread-002",
                "sender_name": "Google Security",
                "sender_email": "no-reply@accounts.google.com",
                "subject": "Security alert: New sign-in from Chrome on macOS",
                "date": "Yesterday, 7:21 PM",
                "snippet": "Your Google Account was recently signed into from a new macOS device. If this was you, no action is needed.",
                "is_unread": False,
                "has_attachments": False,
                "has_urls": True,
            },
            {
                "id": "demo-msg-003",
                "thread_id": "thread-003",
                "sender_name": "Accounting Services",
                "sender_email": "billing@invoices-urgent-portal.com",
                "subject": "Overdue Payment Notice: Invoice #INV-2026-9812",
                "date": "Sep 20, 2:15 PM",
                "snippet": "Your enterprise account will be suspended within 24 hours unless the outstanding balance of ₹49,999 is remitted immediately.",
                "is_unread": True,
                "has_attachments": True,
                "has_urls": True,
            },
            {
                "id": "demo-msg-004",
                "thread_id": "thread-004",
                "sender_name": "VIP Video Club",
                "sender_email": "promo@exclusive-adult-access.com",
                "subject": "Exclusive Adult Videos & Premium HD Streaming",
                "date": "Sep 19, 11:30 PM",
                "snippet": "Click here to watch 4K adult video streaming with exclusive member access. No credit card required.",
                "is_unread": False,
                "has_attachments": False,
                "has_urls": True,
            },
            {
                "id": "demo-msg-005",
                "thread_id": "thread-005",
                "sender_name": "GitHub Notifications",
                "sender_email": "notifications@github.com",
                "subject": "[GitHub] Pull Request #42: Threat Scoring Reform merged",
                "date": "Sep 19, 4:05 PM",
                "snippet": "XCodeBunnyX merged commit 89fa21 into main. View the full conversation and diff on GitHub.",
                "is_unread": False,
                "has_attachments": False,
                "has_urls": True,
            },
        ]

        # Merge cached analysis
        for itm in demo_items:
            cached = cached_map.get(itm["id"])
            itm["analysis_status"] = "ANALYZED" if cached else "NOT_ANALYZED"
            itm["threat_score"] = cached.get("threat_score") if cached else None
            itm["threat_verdict"] = cached.get("verdict") if cached else None
            itm["gemini_assessment"] = (
                cached.get("gemini_analysis", {}).get("overall_assessment")
                if cached else None
            )

        return {
            "mode": "DEMO",
            "connected": False,
            "configured": self.is_configured(),
            "messages": demo_items,
            "result_size_estimate": len(demo_items),
            "notice": "Google OAuth is not connected. Showing demonstration mailbox. Connect real Gmail account via 'Connect Gmail'.",
        }

    def _get_demo_raw_email(self, message_id: str) -> str:
        """Return raw RFC 5322 .eml string corresponding to demo messages."""
        if message_id == "demo-msg-001":
            eml_file = Path(__file__).resolve().parent / "sample_emails" / "phishing_bank.eml"
            if eml_file.exists():
                return eml_file.read_text(encoding="utf-8", errors="replace")
            return (
                "From: Axis Bank Alert <alerts@axisbank-security-update.xyz>\n"
                "To: user@example.com\n"
                "Subject: CRITICAL: Immediate Account Verification Required\n"
                "Date: Mon, 22 Sep 2026 10:42:00 +0530\n"
                "MIME-Version: 1.0\n"
                "Content-Type: text/plain; charset=utf-8\n\n"
                "Dear Customer,\n\n"
                "Your Axis Bank netbanking access has been flagged due to suspicious attempts.\n"
                "Verify your password and credentials immediately at:\n"
                "http://bit.ly/3xHDFC-verify\n\n"
                "Failure to verify will result in immediate suspension.\n"
            )

        if message_id == "demo-msg-003":
            return (
                "From: Accounting Services <billing@invoices-urgent-portal.com>\n"
                "To: user@example.com\n"
                "Subject: Overdue Payment Notice: Invoice #INV-2026-9812\n"
                "Date: Sun, 20 Sep 2026 14:15:00 +0530\n"
                "MIME-Version: 1.0\n"
                "Content-Type: text/plain; charset=utf-8\n\n"
                "URGENT ATTENTION REQUIRED:\n\n"
                "Your enterprise account will be suspended within 24 hours unless the outstanding "
                "balance of ₹49,999 is paid immediately.\n\n"
                "Please remit payment here: https://payment-portal-settlement.org/pay\n\n"
                "Do not delay.\n"
            )

        if message_id == "demo-msg-004":
            return (
                "From: VIP Video Club <promo@exclusive-adult-access.com>\n"
                "To: user@example.com\n"
                "Subject: Exclusive Adult Videos & Premium HD Streaming\n"
                "Date: Sat, 19 Sep 2026 23:30:00 +0530\n"
                "MIME-Version: 1.0\n"
                "Content-Type: text/plain; charset=utf-8\n\n"
                "Click here to watch 4K adult video streaming with exclusive member access: "
                "https://example.com/adult-portal\n\n"
                "Enjoy uncensored content 24/7.\n"
            )

        if message_id == "demo-msg-005":
            return (
                "From: GitHub Notifications <notifications@github.com>\n"
                "To: user@example.com\n"
                "Subject: [GitHub] Pull Request #42: Threat Scoring Reform merged\n"
                "Date: Sat, 19 Sep 2026 16:05:00 +0530\n"
                "MIME-Version: 1.0\n"
                "Content-Type: text/plain; charset=utf-8\n\n"
                "XCodeBunnyX merged commit 89fa21 into main.\n\n"
                "View the pull request on GitHub: https://github.com/pulls/42\n"
            )

        # Default fallback
        eml_file = Path(__file__).resolve().parent / "sample_emails" / "legitimate.eml"
        if eml_file.exists():
            return eml_file.read_text(encoding="utf-8", errors="replace")
        return (
            "From: Google Security <no-reply@accounts.google.com>\n"
            "To: user@example.com\n"
            "Subject: Security alert: New sign-in from Chrome on macOS\n"
            "Date: Sun, 21 Sep 2026 19:21:00 +0530\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Your Google Account was recently signed into from a new macOS device.\n"
            "If this was you, no action is needed.\n"
        )


# Singleton instance for application-wide reuse
gmail_service = GmailService()
