"""
GmailGuard — Gmail Integration & OAuth 2.0 Test Suite
Tests:
1. OAuth 2.0 configuration checks
2. Consent URL generation with least-privilege 'gmail.readonly' scope
3. Token management and server-side storage without secret leaks
4. Message listing with metadata, read/unread states, attachment/URL flags
5. Full raw RFC 5322 extraction (format='raw') for existing pipeline ingestion
6. Persistent caching by gmail_message_id and re-analyze support
7. Demo mode fallback when unauthenticated
8. Disconnect token cleanup
9. REST API endpoints for Gmail integration
"""

import base64
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.api import app
from backend.gmail_service import GmailService, SCOPES
from backend import config


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def gmail_service(tmp_path):
    svc = GmailService()
    svc.token_path = tmp_path / ".test_token.json"
    svc.cache_path = tmp_path / ".test_cache.json"
    return svc


class TestGmailConfiguration:
    def test_is_configured_false_by_default(self, gmail_service):
        with patch.object(config, "GMAIL_CLIENT_ID", ""), patch.object(config, "GMAIL_CLIENT_SECRET", ""):
            assert gmail_service.is_configured() is False

    def test_is_configured_true_with_env(self, gmail_service):
        with patch.object(config, "GMAIL_CLIENT_ID", "dummy_id.apps.googleusercontent.com"), \
             patch.object(config, "GMAIL_CLIENT_SECRET", "dummy_secret"):
            assert gmail_service.is_configured() is True

    def test_scopes_are_least_privilege_read_only(self):
        assert "https://www.googleapis.com/auth/gmail.readonly" in SCOPES
        # Must not contain send, modify, compose or delete permissions
        for scope in SCOPES:
            assert "modify" not in scope
            assert "compose" not in scope
            assert "send" not in scope
            assert "delete" not in scope


class TestGmailOAuthFlow:
    @patch("google_auth_oauthlib.flow.Flow.from_client_config")
    def test_get_authorization_url(self, mock_flow_cls, gmail_service):
        mock_flow = MagicMock()
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth?client_id=test", "state123")
        mock_flow_cls.return_value = mock_flow

        with patch.object(config, "GMAIL_CLIENT_ID", "test_id"), \
             patch.object(config, "GMAIL_CLIENT_SECRET", "test_sec"):
            auth_url, state = gmail_service.get_authorization_url("http://127.0.0.1:8000/api/gmail/oauth2callback")
            assert "accounts.google.com" in auth_url
            assert state == "state123"

    @patch("google_auth_oauthlib.flow.Flow.from_client_config")
    def test_handle_oauth_callback_saves_token(self, mock_flow_cls, gmail_service):
        mock_creds = MagicMock()
        mock_creds.token = "ya29.test_token"
        mock_creds.refresh_token = "1//test_refresh"
        mock_creds.token_uri = "https://oauth2.googleapis.com/token"
        mock_creds.client_id = "test_id"
        mock_creds.client_secret = "test_sec"
        mock_creds.scopes = SCOPES

        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow_cls.return_value = mock_flow

        with patch.object(config, "GMAIL_CLIENT_ID", "test_id"), \
             patch.object(config, "GMAIL_CLIENT_SECRET", "test_sec"), \
             patch.object(gmail_service, "get_user_info", return_value={"email": "analyst@example.com"}):
            res = gmail_service.handle_oauth_callback("test_auth_code", "http://127.0.0.1:8000/api/gmail/oauth2callback")
            assert res["email"] == "analyst@example.com"
            assert os.path.exists(gmail_service.token_path)

    def test_disconnect_removes_token(self, gmail_service):
        gmail_service.token_path.write_text('{"token": "test"}', encoding="utf-8")
        assert os.path.exists(gmail_service.token_path)
        res = gmail_service.disconnect()
        assert res is True
        assert not os.path.exists(gmail_service.token_path)

    def test_pkce_code_verifier_saved_and_passed(self, gmail_service):
        mock_flow = MagicMock()
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/test", "test_state_123")
        mock_flow.code_verifier = "test_code_verifier_abc_123"

        with patch("google_auth_oauthlib.flow.Flow.from_client_config", return_value=mock_flow):
            auth_url, state = gmail_service.get_authorization_url("http://127.0.0.1:8000/api/gmail/oauth2callback")
            assert state == "test_state_123"
            verifier, r_uri = gmail_service._pop_oauth_state("test_state_123")
            assert verifier == "test_code_verifier_abc_123"
            assert r_uri == "http://127.0.0.1:8000/api/gmail/oauth2callback"

    def test_pkce_fallback_when_state_mismatched(self, gmail_service):
        # Save a state entry
        gmail_service._save_oauth_state("known_state_xyz", "verifier_xyz_999", "http://127.0.0.1:8000/api/gmail/oauth2callback")
        # Pop with unknown state
        verifier, r_uri = gmail_service._pop_oauth_state("unknown_state")
        assert verifier == "verifier_xyz_999"
        assert r_uri == "http://127.0.0.1:8000/api/gmail/oauth2callback"


class TestGmailMessageRetrievalAndNormalization:
    @patch("googleapiclient.discovery.build")
    def test_raw_message_to_rfc5322_normalization(self, mock_build, gmail_service):
        sample_eml = (
            "From: security@axisbank-security-update.xyz\r\n"
            "To: victim@example.com\r\n"
            "Subject: Immediate Action Required\r\n"
            "\r\n"
            "Please click http://example.com/login"
        )
        b64_raw = base64.urlsafe_b64encode(sample_eml.encode("utf-8")).decode("ascii")

        mock_api_message = {
            "id": "msg-12345",
            "raw": b64_raw
        }

        mock_service = MagicMock()
        mock_service.users().messages().get.return_value.execute.return_value = mock_api_message
        mock_build.return_value = mock_service

        with patch.object(gmail_service, "_get_credentials", return_value=MagicMock()):
            raw_rfc5322 = gmail_service.get_message_raw("msg-12345")
            assert "From: security@axisbank-security-update.xyz" in raw_rfc5322
            assert "Subject: Immediate Action Required" in raw_rfc5322
            assert "http://example.com/login" in raw_rfc5322

    def test_demo_messages_fallback(self, gmail_service):
        # When unauthenticated, list_messages returns demo emails
        res = gmail_service.list_messages(max_results=5)
        assert "messages" in res
        assert len(res["messages"]) >= 4
        assert res["mode"] == "DEMO"
        # Check that expected sample scenarios exist
        ids = [m["id"] for m in res["messages"]]
        assert "demo-msg-001" in ids  # Phishing
        assert "demo-msg-002" in ids  # Legitimate Google alert
        assert "demo-msg-003" in ids  # Payment urgent notice
        assert "demo-msg-004" in ids  # Adult content link

    def test_caching_and_reanalyze(self, gmail_service):
        msg_id = "test-msg-009"
        mock_result = {
            "threat_score": 75,
            "verdict": "HIGH_RISK",
            "case_id": "CASE-TEST-009"
        }

        # Cache result
        gmail_service.save_cached_analysis(msg_id, mock_result)
        cached = gmail_service.get_cached_analysis(msg_id)
        assert cached is not None
        assert cached["threat_score"] == 75
        assert cached["verdict"] == "HIGH_RISK"

        # Re-analyzing with mock
        new_result = {
            "threat_score": 80,
            "verdict": "CRITICAL",
            "case_id": "CASE-TEST-009B"
        }
        gmail_service.save_cached_analysis(msg_id, new_result)
        cached_updated = gmail_service.get_cached_analysis(msg_id)
        assert cached_updated["threat_score"] == 80


class TestGmailApiEndpoints:
    def test_gmail_status_endpoint(self, client):
        res = client.get("/api/gmail/status")
        assert res.status_code == 200
        data = res.json()
        assert "connected" in data
        assert "configured" in data

    def test_gmail_messages_endpoint(self, client):
        res = client.get("/api/gmail/messages")
        assert res.status_code == 200
        data = res.json()
        assert "messages" in data
        assert len(data["messages"]) > 0

    def test_gmail_analyze_endpoint_with_demo_message(self, client):
        # Calling analyze on demo-msg-002 (Google legitimate security alert)
        res = client.post("/api/gmail/analyze/demo-msg-002?reanalyze=false")
        assert res.status_code == 200
        data = res.json()
        assert "threat_score" in data
        assert "verdict" in data
        assert "gemini_analysis" in data
        assert data.get("gmail_message_id") == "demo-msg-002"

    def test_gmail_auth_endpoint_redirects(self, client):
        with patch("backend.gmail_service.gmail_service.get_authorization_url", return_value=("https://accounts.google.com/test", "state123")):
            res = client.get("/api/gmail/auth", follow_redirects=False)
            assert res.status_code in (302, 307)
            assert "accounts.google.com" in res.headers["location"]

    def test_gmail_auth_url_endpoint(self, client):
        with patch("backend.gmail_service.gmail_service.get_authorization_url", return_value=("https://accounts.google.com/test", "state123")):
            res = client.get("/api/gmail/auth-url")
            assert res.status_code == 200
            data = res.json()
            assert "auth_url" in data
            assert "accounts.google.com" in data["auth_url"]


class TestPerEmailIndependentAnalysis:
    """
    Regression test suite verifying that:
    1. Analyzing one Gmail message does not remove Analyze actions from other Gmail messages.
    2. Per-email analysis state is completely independent.
    3. Analyzing Email A does not mark Email B, C, D as analyzed or overwrite their results.
    4. Caching keys analysis results specifically by Gmail message ID.
    5. Listing messages preserves individual analysis statuses across multiple emails.
    """
    def test_analyzing_one_message_preserves_other_messages_pending_state(self, client, tmp_path):
        import backend.gmail_service as gs
        isolated_cache = tmp_path / ".test_isolation_cache.json"
        with patch.object(gs.gmail_service, "cache_path", isolated_cache):
            # 1. Fetch initial message list
            res = client.get("/api/gmail/messages")
            assert res.status_code == 200
            messages = res.json()["messages"]
            assert len(messages) >= 3

            id_a = messages[0]["id"]
            id_b = messages[1]["id"]
            id_c = messages[2]["id"]

            # 2. Analyze Message A only
            res_a = client.post(f"/api/gmail/analyze/{id_a}?reanalyze=false")
            assert res_a.status_code == 200
            data_a = res_a.json()
            assert data_a["gmail_message_id"] == id_a
            assert data_a.get("threat_score") is not None

            # 3. Re-fetch inbox message list - verify Message A has analysis data while Message B and C remain unanalyzed
            res_inbox = client.get("/api/gmail/messages")
            assert res_inbox.status_code == 200
            inbox_msgs = {m["id"]: m for m in res_inbox.json()["messages"]}

            # Message A is analyzed
            assert inbox_msgs[id_a]["threat_score"] == data_a["threat_score"]
            assert inbox_msgs[id_a]["analysis_status"] == "ANALYZED"

            # Message B and C are strictly NOT analyzed (pending)
            assert inbox_msgs[id_b].get("threat_score") is None
            assert inbox_msgs[id_b]["analysis_status"] == "NOT_ANALYZED"
            assert inbox_msgs[id_c].get("threat_score") is None
            assert inbox_msgs[id_c]["analysis_status"] == "NOT_ANALYZED"

            # 4. Analyze Message B independently
            res_b = client.post(f"/api/gmail/analyze/{id_b}?reanalyze=false")
            assert res_b.status_code == 200
            data_b = res_b.json()
            assert data_b["gmail_message_id"] == id_b

            # 5. Verify both A and B are analyzed with distinct independent results, and C remains NOT_ANALYZED
            res_inbox2 = client.get("/api/gmail/messages")
            inbox_msgs2 = {m["id"]: m for m in res_inbox2.json()["messages"]}

            assert inbox_msgs2[id_a]["threat_score"] == data_a["threat_score"]
            assert inbox_msgs2[id_b]["threat_score"] == data_b["threat_score"]
            assert inbox_msgs2[id_c].get("threat_score") is None
            assert inbox_msgs2[id_c]["analysis_status"] == "NOT_ANALYZED"

    def test_analysis_results_keyed_by_message_id_do_not_collide(self, gmail_service):
        report_1 = {"threat_score": 92, "verdict": "CRITICAL", "case_id": "CASE-1"}
        report_2 = {"threat_score": 15, "verdict": "SAFE", "case_id": "CASE-2"}

        gmail_service.save_cached_analysis("msg-alpha", report_1)
        gmail_service.save_cached_analysis("msg-beta", report_2)

        res_alpha = gmail_service.get_cached_analysis("msg-alpha")
        res_beta = gmail_service.get_cached_analysis("msg-beta")
        res_gamma = gmail_service.get_cached_analysis("msg-gamma")

        assert res_alpha["threat_score"] == 92
        assert res_alpha["verdict"] == "CRITICAL"
        assert res_beta["threat_score"] == 15
        assert res_beta["verdict"] == "SAFE"
        assert res_gamma is None


