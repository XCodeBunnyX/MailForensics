"""Unit tests for threat_scorer.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from ..authentication_analyzer import AuthResult
from ..ip_intelligence import IPIntelligence, IPRecord
from ..url_analyzer import URLAnalysis
from ..attachment_analyzer import AttachmentAnalysis
from ..ml_classifier import MLResult
from ..domain_intelligence import DomainIntelligence
from ..header_analyzer import HeaderIntelligence, RelayHop
from ..threat_scorer import compute_threat_score, ThreatScore


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
        from ..url_analyzer import URLFinding
        from ..attachment_analyzer import AttachmentFinding

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

    # ── Risk Accumulation Tests ─────────────────────────────────

    def test_risk_accumulation_url_adds_on_top_never_dilutes(self):
        """Adding a suspicious URL must boost the score on top of base score, never dilute it."""
        from ..url_analyzer import URLFinding, URLAnalysis

        # Base email without URLs
        base_result = self._score(
            ml=_make_phishing_ml(),
            auth=_make_auth("PASS", "PASS", "PASS"),
            domain=_make_domain_intel("clean", 20),
            urls=_make_url_analysis(total=0, suspicious=0),
        )
        assert base_result.threat_score >= 40

        # Same email with suspicious URL (score ~60)
        susp_finding = URLFinding(
            url="http://185.220.101.45/verify", domain="185.220.101.45", tld="",
            risk_score=60, is_ip_url=True, is_url_shortener=False,
            has_suspicious_tld=False, excessive_subdomains=False,
            has_suspicious_chars=False, suspicious_char_matches=[],
            uses_https=False, display_href_mismatch=False,
            domain_reputation="suspicious", domain_rep_score=60,
            reasons=["Direct IP URL"],
        )
        susp_urls = URLAnalysis(total_count=1, suspicious_count=1, findings=[susp_finding], all_urls=[], limitations=[])

        boosted_result = self._score(
            ml=_make_phishing_ml(),
            auth=_make_auth("PASS", "PASS", "PASS"),
            domain=_make_domain_intel("clean", 20),
            urls=susp_urls,
        )

        assert boosted_result.threat_score > base_result.threat_score
        assert 70 <= boosted_result.threat_score <= 95

    def test_clean_url_does_not_dilute_base_score(self):
        """A clean URL (score <= 20) must contribute 0 bonus risk and NOT dilute the base score."""
        from ..url_analyzer import URLFinding, URLAnalysis

        no_url_result = self._score(
            ml=_make_phishing_ml(),
            auth=_make_auth("PASS", "PASS", "PASS"),
            domain=_make_domain_intel("clean", 20),
            urls=_make_url_analysis(total=0, suspicious=0),
        )

        clean_finding = URLFinding(
            url="https://google.com", domain="google.com", tld="com",
            risk_score=10, is_ip_url=False, is_url_shortener=False,
            has_suspicious_tld=False, excessive_subdomains=False,
            has_suspicious_chars=False, suspicious_char_matches=[],
            uses_https=True, display_href_mismatch=False,
            domain_reputation="clean", domain_rep_score=0,
            reasons=[],
        )
        clean_urls = URLAnalysis(total_count=1, suspicious_count=0, findings=[clean_finding], all_urls=[], limitations=[])

        clean_url_result = self._score(
            ml=_make_phishing_ml(),
            auth=_make_auth("PASS", "PASS", "PASS"),
            domain=_make_domain_intel("clean", 20),
            urls=clean_urls,
        )

        # Clean URL must not reduce the threat score below the no-URL score
        assert clean_url_result.threat_score >= no_url_result.threat_score

    def test_multiple_corroborating_signals_boost_to_critical(self):
        """Multiple corroborating threat signals (ML + Domain + URL) reinforce each other to 90+."""
        from ..url_analyzer import URLFinding, URLAnalysis

        susp_finding = URLFinding(
            url="http://185.220.101.45/login", domain="185.220.101.45", tld="",
            risk_score=65, is_ip_url=True, is_url_shortener=False,
            has_suspicious_tld=False, excessive_subdomains=False,
            has_suspicious_chars=False, suspicious_char_matches=[],
            uses_https=False, display_href_mismatch=False,
            domain_reputation="suspicious", domain_rep_score=65,
            reasons=["Direct IP URL"],
        )
        susp_urls = URLAnalysis(total_count=1, suspicious_count=1, findings=[susp_finding], all_urls=[], limitations=[])

        multi_threat = self._score(
            ml=_make_phishing_ml(),
            auth=_make_auth("FAIL", "FAIL", "FAIL"),
            domain=_make_domain_intel("suspicious", 60),
            urls=susp_urls,
        )
        assert multi_threat.threat_score >= 90
        assert multi_threat.verdict == "CRITICAL"

    def test_malicious_payload_override_floor(self):
        """An independently malicious payload (e.g. 95) sets a critical floor even with benign content."""
        from ..url_analyzer import URLFinding, URLAnalysis

        bad_finding = URLFinding(
            url="http://malware-drop.ru/loader", domain="malware-drop.ru", tld="ru",
            risk_score=95, is_ip_url=False, is_url_shortener=False,
            has_suspicious_tld=True, excessive_subdomains=False,
            has_suspicious_chars=False, suspicious_char_matches=[],
            uses_https=False, display_href_mismatch=False,
            domain_reputation="malicious", domain_rep_score=95,
            reasons=["Known malware host"],
        )
        bad_urls = URLAnalysis(total_count=1, suspicious_count=1, findings=[bad_finding], all_urls=[], limitations=[])

        result = self._score(
            ml=_make_clean_ml(),
            auth=_make_auth("PASS", "PASS", "PASS"),
            domain=_make_domain_intel("clean", 0),
            urls=bad_urls,
        )
        assert result.threat_score >= 95
        assert result.verdict == "CRITICAL"

    def test_case_1_benign_gmail_no_url_no_attachment(self):
        """TEST 1 — BENIGN: Normal Gmail-to-Gmail email with no URL and no attachment -> Low risk / CLEAN."""
        from ..email_parser import parse_email
        from ..ml_classifier import classify_email
        from ..domain_intelligence import analyze_domain

        raw_eml = (
            "MIME-Version: 1.0\n"
            "Date: Mon, 21 Sep 2026 14:56:22 +0530\n"
            "Message-ID: <CAJd7kVt_Ve-GFKL==rt0k3KG4owSQk_Om=Yg-0Jj7-97MDNdsw@mail.gmail.com>\n"
            "Subject: Test Email\n"
            "From: Prakhar Rathore <prakharrathore006@gmail.com>\n"
            "To: Prakhar Rathore <prakharrathore006@gmail.com>\n"
            "Content-Type: multipart/alternative; boundary=\"000000000000f462ca065bfad786\"\n\n"
            "--000000000000f462ca065bfad786\n"
            "Content-Type: text/plain; charset=\"UTF-8\"\n\n"
            "Hi how are you?\n\n"
            "--000000000000f462ca065bfad786\n"
            "Content-Type: text/html; charset=\"UTF-8\"\n\n"
            "<div dir=\"ltr\">Hi how are you?</div>\n\n"
            "--000000000000f462ca065bfad786--"
        )
        parsed = parse_email(raw_eml)
        ml = classify_email(parsed.text_body, parsed.html_body, parsed.subject)
        dom = analyze_domain(parsed.sender_domain)

        score = self._score(ml=ml, domain=dom)
        assert score.threat_score <= 25
        assert score.verdict in ("CLEAN", "LOW_RISK")
        assert score.sub_scores["ml"] <= 20
        assert len(score.evidence) == 0

    def test_case_2_benign_multipart_alternative_gmail(self):
        """TEST 2 — BENIGN: Normal multipart/alternative Gmail email with PASS authentication -> Low risk."""
        from ..email_parser import parse_email
        from ..ml_classifier import classify_email
        from ..domain_intelligence import analyze_domain

        raw_eml = (
            "MIME-Version: 1.0\n"
            "Date: Mon, 21 Sep 2026 14:56:22 +0530\n"
            "Subject: Meeting Notes\n"
            "From: Alice <alice@gmail.com>\n"
            "To: Bob <bob@gmail.com>\n"
            "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n"
            "Content-Type: multipart/alternative; boundary=\"boundary123\"\n\n"
            "--boundary123\n"
            "Content-Type: text/plain; charset=\"UTF-8\"\n\n"
            "Here are the notes from our discussion earlier.\n\n"
            "--boundary123\n"
            "Content-Type: text/html; charset=\"UTF-8\"\n\n"
            "<div>Here are the notes from our discussion earlier.</div>\n\n"
            "--boundary123--"
        )
        parsed = parse_email(raw_eml)
        ml = classify_email(parsed.text_body, parsed.html_body, parsed.subject)
        dom = analyze_domain(parsed.sender_domain)
        auth = _make_auth("PASS", "PASS", "PASS")

        score = self._score(ml=ml, domain=dom, auth=auth)
        assert score.threat_score <= 25
        assert score.verdict in ("CLEAN", "LOW_RISK")

    def test_case_3_phishing_lookalike_url_phishing_language(self):
        """TEST 3 — PHISHING: Lookalike domain + suspicious URL + phishing language -> HIGH_RISK or CRITICAL."""
        from ..url_analyzer import URLFinding, URLAnalysis

        susp_url = URLFinding(
            url="https://rnicrosoft-verify.com/login", domain="rnicrosoft-verify.com", tld="com",
            risk_score=75, is_ip_url=False, is_url_shortener=False,
            has_suspicious_tld=False, excessive_subdomains=False,
            has_suspicious_chars=False, suspicious_char_matches=[],
            uses_https=True, display_href_mismatch=False,
            domain_reputation="suspicious", domain_rep_score=75,
            reasons=["Credential harvesting target"],
        )
        urls = URLAnalysis(total_count=1, suspicious_count=1, findings=[susp_url], all_urls=[], limitations=[])

        score = self._score(
            ml=_make_phishing_ml(),
            domain=_make_domain_intel("suspicious", 60),
            urls=urls,
        )
        assert score.threat_score >= 70
        assert score.verdict in ("HIGH_RISK", "CRITICAL")

    def test_case_4_authentication_pass_does_not_override_strong_phishing(self):
        """TEST 4 — AUTHENTICATION: Valid PASS auth provides positive evidence but does NOT override phishing."""
        from ..url_analyzer import URLFinding, URLAnalysis

        susp_url = URLFinding(
            url="https://phish.example.com/steal", domain="phish.example.com", tld="com",
            risk_score=70, is_ip_url=False, is_url_shortener=False,
            has_suspicious_tld=False, excessive_subdomains=False,
            has_suspicious_chars=False, suspicious_char_matches=[],
            uses_https=True, display_href_mismatch=False,
            domain_reputation="suspicious", domain_rep_score=70,
            reasons=["Phishing link"],
        )
        urls = URLAnalysis(total_count=1, suspicious_count=1, findings=[susp_url], all_urls=[], limitations=[])

        score = self._score(
            ml=_make_phishing_ml(),
            auth=_make_auth("PASS", "PASS", "PASS"),
            domain=_make_domain_intel("suspicious", 50),
            urls=urls,
        )
        # Auth pass lowers base score slightly, but strong phishing signals keep it high risk
        assert score.threat_score >= 70
        assert score.verdict in ("HIGH_RISK", "CRITICAL")
        # Positive evidence contains the auth pass
        assert any(e.signal == "SPF" and e.is_positive for e in score.positive_evidence)

    def test_case_5_missing_signals_do_not_increase_threat_score(self):
        """TEST 5 — MISSING SIGNALS: No URL / no attachment / unavailable IP should NOT increase threat score."""
        # Clean baseline with clean ML and clean domain
        clean_ml = _make_clean_ml()
        clean_domain = _make_domain_intel("clean", 0)

        score_missing_payloads = self._score(
            ml=clean_ml,
            domain=clean_domain,
            urls=_make_url_analysis(total=0, suspicious=0),
            atts=_make_att_analysis(total=0, suspicious=0),
            ip=_make_ip_intel("none", 50),
        )

        assert score_missing_payloads.threat_score <= 25
        assert score_missing_payloads.verdict in ("CLEAN", "LOW_RISK")

    def test_case_6_mixed_signals_reflect_actual_available_evidence(self):
        """TEST 6 — MIXED: Some suspicious signals, some legitimate signals -> reflects available evidence."""
        score = self._score(
            ml=_make_clean_ml(),                     # Legitimate language (low risk)
            auth=_make_auth("SOFTFAIL", "PASS", "NONE"), # Softfail auth (moderate risk)
            domain=_make_domain_intel("clean", 10),  # Clean domain (low risk)
            urls=_make_url_analysis(total=0, suspicious=0),
        )
        # Mixed signals should produce an intermediate score (not 0, and not 80+)
        assert 15 <= score.threat_score <= 55
        assert score.verdict in ("CLEAN", "LOW_RISK", "MEDIUM_RISK")
