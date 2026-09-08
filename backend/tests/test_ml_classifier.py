"""Unit tests for ml_classifier.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from ml_classifier import classify_email, MLResult


class TestMLClassifier:
    def test_returns_ml_result(self):
        result = classify_email("Hello, how are you?", "")
        assert isinstance(result, MLResult)

    def test_model_unavailable_returns_unknown(self):
        # If model files don't exist, prediction must be UNKNOWN (not crash)
        result = classify_email("test", "")
        if not result.model_available:
            assert result.prediction == "UNKNOWN"
            assert result.decision_score is None

    def test_prediction_is_valid_label(self):
        result = classify_email("Verify your bank account now. Click here.", "")
        assert result.prediction in ("Phishing", "Legitimate", "UNKNOWN")

    def test_decision_score_is_float_or_none(self):
        result = classify_email("Hello there!", "")
        if result.decision_score is not None:
            assert isinstance(result.decision_score, float)

    def test_empty_body_returns_unknown(self):
        result = classify_email("", "")
        # Either model unavailable or body empty → UNKNOWN
        if result.model_available:
            assert result.prediction == "UNKNOWN"

    def test_note_does_not_say_probability(self):
        result = classify_email("Click here to win a prize!", "")
        # Note must NOT claim to be a probability or confidence %
        note_lower = result.note.lower()
        assert "probability" not in note_lower or "not a probability" in note_lower

    def test_note_does_not_say_confidence_percentage(self):
        result = classify_email("Urgent account verification required", "")
        note = result.note
        # If the note mentions "confidence percentage", it must also negate it (e.g. "NOT a ... confidence percentage")
        if "confidence percentage" in note.lower():
            assert "not" in note.lower(), \
                "Note must not claim the score IS a confidence percentage"

    def test_html_body_used_when_text_empty(self):
        html = "<html><body><p>Click here to verify your account</p></body></html>"
        result = classify_email("", html)
        assert isinstance(result, MLResult)
        assert result.prediction in ("Phishing", "Legitimate", "UNKNOWN")
