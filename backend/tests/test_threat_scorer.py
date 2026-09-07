"""Unit tests for threat_scorer.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from authentication_analyzer import AuthResult
from ip_intelligence import IPIntelligence, IPRecord
from url_analyzer import URLAnalysis
from attachment_analyzer import AttachmentAnalysis
from ml_classifier import MLResult
from domain_intelligence import DomainIntelligence
from header_analyzer import HeaderIntelligence, RelayHop
from threat_scorer import compute_threat_score, ThreatScore


def _make_auth(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN") -> AuthResult:
    fail_set = {"FAIL", "SOFTFAIL", "PERMERROR"}
    any_failed = any(r in fail_set for r in [spf, dkim, dmarc])
    all_passed = all(r == "PASS" for r in [spf, dkim, dmarc])
    return AuthResult(
        spf=spf, dkim=dkim, dmarc=dmarc,
        spf_detail=spf, dkim_detail=dkim, dmarc_detail=dmarc,
        all_passed=all_passed, any_failed=any_failed, summary="test"
    )


def _make_ip_intel(reputation="unknown", score=50) -> IPIntelligence:
    records = []
    if reputation != "none":
        records = [IPRecord(
            ip="1.2.3.4", reputation=reputation,
            reputation_score=score, categories=[], source="MOCK",
        )]
    return IPIntelligence(
        public_ips=["1.2.3.4"] if reputation != "none" else [],
        records=records,
        any_malicious=(reputation == "malicious"),
        any_suspicious=(reputation == "suspicious"),
        max_reputation_score=score,
        limitations=[],
    )


def _make_clean_ml() -> MLResult:
    return MLResult(prediction="Legitimate", decision_score=-1.5,
                    model_available=True, note="test")


def _make_phishing_ml() -> MLResult:
    return MLResult(prediction="Phishing", decision_score=2.1,
                    model_available=True, note="test")


def _make_unknown_ml() -> MLResult:
    return MLResult(prediction="UNKNOWN", decision_score=None,
                    model_available=False, note="no model")


def _make_url_analysis(suspicious=0, total=0) -> URLAnalysis:
    return URLAnalysis(total_count=total, suspicious_count=suspicious,
                       findings=[], all_urls=[], limitations=[])


def _make_att_analysis(suspicious=0, total=0) -> AttachmentAnalysis:
    return AttachmentAnalysis(total_count=total, suspicious_count=suspicious, findings=[])


def _make_domain_intel(reputation="unknown", score=50) -> DomainIntelligence:
    return DomainIntelligence(
        domain="example.com", reputation=reputation, reputation_score=score,
        categories=[], age_days=None, registrar=None, virustotal_flags=None,
        is_suspicious_tld=False, tld=".com", is_typosquat=False,
        typosquat_target="", risk_score=score, reasons=[], source="MOCK"
    )


def _make_header_intel() -> HeaderIntelligence:
    return HeaderIntelligence(
        relay_chain=[], x_originating_ip="", x_mailer="",
        reply_to_differs=False, reply_to_address="",
        sender_email="test@example.com", sender_domain="example.com",
        identified_providers=[], infrastructure_note="", warnings=[]
    )


class TestThreatScorer:
    def _score(self, ml=None, auth=None, ip=None, domain=None,
               urls=None, atts=None) -> ThreatScore:
        return compute_threat_score(
            ml=ml or _make_unknown_ml(),
            auth=auth or _make_auth(),
            ip_intel=ip or _make_ip_intel("none", 50),
            domain_intel=domain or _make_domain_intel(),
            url_analysis=urls or _make_url_analysis(),
            att_analysis=atts or _make_att_analysis(),
            header_intel=_make_header_intel(),
        )

    def test_returns_threat_score(self):
        result = self._score()
        assert isinstance(result, ThreatScore)

    def test_score_within_range(self):
        result = self._score()
        assert 0 <= result.threat_score <= 100

    def test_all_pass_auth_lowers_score(self):
        clean = self._score(auth=_make_auth("PASS", "PASS", "PASS"))
        failed = self._score(auth=_make_auth("FAIL", "FAIL", "FAIL"))
        assert clean.threat_score < failed.threat_score

    def test_phishing_ml_raises_score(self):
        phish = self._score(ml=_make_phishing_ml())
        legit = self._score(ml=_make_clean_ml())
        assert phish.threat_score > legit.threat_score

    def test_unknown_ml_neutral(self):
        unknown = self._score(ml=_make_unknown_ml())
        # Score should be in middle range (not 0, not 100)
        assert 10 <= unknown.threat_score <= 80

    def test_malicious_ip_raises_score(self):
        malicious = self._score(ip=_make_ip_intel("malicious", 95))
        clean = self._score(ip=_make_ip_intel("clean", 5))
        assert malicious.threat_score > clean.threat_score

    def test_unknown_ip_is_neutral(self):
        result = self._score(ip=_make_ip_intel("unknown", 50))
        # 50 is neutral — score should not be extreme
        assert 5 <= result.threat_score <= 85

    def test_verdict_critical_for_high_score(self):
        # Drive ALL six signals high to push weighted score above 70
        from url_analyzer import URLFinding
        from attachment_analyzer import AttachmentFinding

        # High-risk URL analysis
        bad_url = URLFinding(
            url="http://185.234.219.47/phish", domain="185.234.219.47", tld="",
            risk_score=90, is_ip_url=True, is_url_shortener=False,
            has_suspicious_tld=False, excessive_subdomains=False,
            has_suspicious_chars=False, suspicious_char_matches=[],
            uses_https=False, display_href_mismatch=False,
            domain_reputation="malicious", domain_rep_score=90,
            reasons=["IP URL"],
        )
        bad_urls = URLAnalysis(
            total_count=2, suspicious_count=2,
            findings=[bad_url], all_urls=[], limitations=[],
        )

        # High-risk attachment analysis
        bad_att = AttachmentFinding(
            filename="evil.exe", extension=".exe",
            content_type="application/x-msdownload",
            size_bytes=1000, size_mb=0.001,
            is_dangerous_extension=True, is_archive=False,
            is_macro_enabled=False, has_double_extension=False,
            suspicious_filename_keywords=[], magic_byte_matches=[],
            size_exceeds_limit=False, mime_extension_mismatch=False,
            risk_score=85, reasons=["dangerous extension"],
        )
        bad_atts = AttachmentAnalysis(
            total_count=1, suspicious_count=1, findings=[bad_att]
        )

        result = compute_threat_score(
            ml=_make_phishing_ml(),
            auth=_make_auth("FAIL", "FAIL", "FAIL"),
            ip_intel=_make_ip_intel("malicious", 95),
            domain_intel=_make_domain_intel("malicious", 90),
            url_analysis=bad_urls,
            att_analysis=bad_atts,
            header_intel=_make_header_intel(),
        )
        assert result.verdict in ("HIGH_RISK", "CRITICAL"), (
            f"Expected HIGH_RISK or CRITICAL, got {result.verdict} "
            f"(score={result.threat_score})"
        )

    def test_verdict_clean_for_low_score(self):
        result = self._score(
            ml=_make_clean_ml(),
            auth=_make_auth("PASS", "PASS", "PASS"),
            ip=_make_ip_intel("clean", 5),
            domain=_make_domain_intel("clean", 5),
        )
        assert result.verdict in ("CLEAN", "LOW_RISK")

    def test_evidence_list_populated_on_failures(self):
        result = self._score(
            ml=_make_phishing_ml(),
            auth=_make_auth("FAIL", "FAIL", "FAIL"),
        )
        assert len(result.evidence) > 0

    def test_positive_evidence_on_all_pass(self):
        result = self._score(
            auth=_make_auth("PASS", "PASS", "PASS"),
            ml=_make_clean_ml(),
        )
        assert len(result.positive_evidence) > 0

    def test_weights_used_sum_to_one(self):
        result = self._score()
        total = sum(result.weights_used.values())
        assert abs(total - 1.0) < 0.001
