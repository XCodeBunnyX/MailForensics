"""
GmailGuard — ML Classifier

Wrapper around the existing GmailGuard NLP model:
  - TF-IDF Vectorizer  (gmailguard_tfidf.pkl)
  - LinearSVC          (gmailguard_svm.pkl)

Rules:
  - The model is ONE signal in a larger system, NOT the final decision-maker.
  - LinearSVC decision_function output is a raw score, NOT a probability.
  - We never call it 'confidence' or 'probability'.
  - If the model files are missing, we degrade gracefully to UNKNOWN.
"""

from __future__ import annotations

import os
import re
import html
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import config


@dataclass
class MLResult:
    """Result from the NLP/ML classifier."""
    prediction: str          # "Phishing" | "Legitimate" | "UNKNOWN"
    decision_score: Optional[float]  # Raw LinearSVC decision_function value (not a probability)
    model_available: bool    # False if pkl files were not found
    note: str                # Interpretation note for the analyst


def _load_models() -> tuple[object, object] | tuple[None, None]:
    """
    Attempt to load the TF-IDF vectorizer and SVM model from disk.
    Supports both joblib and pickle formats.
    Returns (vectorizer, model) or (None, None) on failure.
    """
    base_dir = Path(__file__).parent
    vec_path = base_dir / config.ML_VECTORIZER_PATH
    mdl_path = base_dir / config.ML_MODEL_PATH

    if not vec_path.exists() or not mdl_path.exists():
        return None, None

    try:
        import joblib
        vectorizer = joblib.load(vec_path)
        model = joblib.load(mdl_path)
        return vectorizer, model
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: plain pickle
    try:
        import pickle
        with open(vec_path, "rb") as f:
            vectorizer = pickle.load(f)
        with open(mdl_path, "rb") as f:
            model = pickle.load(f)
        return vectorizer, model
    except Exception:
        return None, None


# Load models once at module import time
_VECTORIZER, _MODEL = _load_models()


def _clean_text(text: str) -> str:
    """Basic text cleaning before vectorization."""
    # Decode HTML entities
    text = html.unescape(text)
    # Strip HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def classify_email(text_body: str, html_body: str, subject: str = "") -> MLResult:
    """
    Classify the email content using the pre-trained SVM model.

    Args:
        text_body: Plain-text body.
        html_body: HTML body (will be stripped if used).
        subject: Email Subject line (optional, included in linguistic context).

    Returns:
        MLResult with prediction and raw decision score.
    """
    if _VECTORIZER is None or _MODEL is None:
        return MLResult(
            prediction="UNKNOWN",
            decision_score=None,
            model_available=False,
            note=(
                "ML model files not found at "
                f"'{config.ML_MODEL_PATH}' / '{config.ML_VECTORIZER_PATH}'. "
                "Drop gmailguard_svm.pkl and gmailguard_tfidf.pkl into "
                "the backend/models/ directory to enable ML classification. "
                "Other signals are still used for scoring."
            ),
        )

    # Prefer plain text; fall back to stripped HTML
    body_text = _clean_text(text_body) if text_body.strip() else _clean_text(html_body)
    subj_clean = _clean_text(subject) if subject.strip() else ""

    if subj_clean and body_text:
        content = f"{subj_clean}\n\n{body_text}"
    elif subj_clean:
        content = subj_clean
    else:
        content = body_text

    if not content.strip():
        return MLResult(
            prediction="UNKNOWN",
            decision_score=None,
            model_available=True,
            note="Email body is empty — ML classification not possible.",
        )

    try:
        features = _VECTORIZER.transform([content])

        # LinearSVC decision_function: positive → one class, negative → other
        decision_score: Optional[float] = None
        if hasattr(_MODEL, "decision_function"):
            scores = _MODEL.decision_function(features)
            decision_score = float(scores[0])

        intercept = float(getattr(_MODEL, "intercept_", [0.0])[0])

        # If no vocabulary features match (e.g. stop words or unseen tokens only),
        # there is zero linguistic evidence of phishing.
        if getattr(features, "nnz", 0) == 0:
            normalized = "Legitimate"
            decision_score = 0.0
        else:
            # Model intercept is +0.1755; neutral text with near-zero feature weights
            # produces ~0.176. A sample is only considered Phishing when there is
            # genuine positive discriminant evidence above the baseline intercept.
            # In short emails (< 25 words), common tokens like "com" or "www" can artificially
            # inflate the TF-IDF vector without any actual phishing intent.
            word_count = len(content.split())
            phish_keywords = {
                "password", "bank", "banking", "account", "verify", "verification",
                "suspend", "suspended", "login", "log in", "credential", "security alert",
                "urgent", "action required", "wire", "invoice", "payment", "unauthorized",
                "confirm", "update your", "expire", "ssn", "compromised", "reset", "billing",
                "immediate", "limited time", "locked", "reactivate", "tax refund", "transfer"
            }
            content_lower = content.lower()
            has_phish_intent = any(kw in content_lower for kw in phish_keywords)

            if word_count < 25 and not has_phish_intent:
                threshold = max(0.85, intercept + 0.65)
            else:
                threshold = max(0.25, intercept + 0.10)

            if decision_score is not None and decision_score >= threshold:
                normalized = "Phishing"
            elif decision_score is not None:
                normalized = "Legitimate"
            else:
                prediction_label = _MODEL.predict(features)[0]
                label_lower = str(prediction_label).lower()
                normalized = "Phishing" if ("phish" in label_lower or label_lower in ("1", "true", "spam")) else "Legitimate"

        note = (
            f"LinearSVC decision score: {decision_score:.4f}. "
            "This is a raw discriminant score, NOT a probability or confidence percentage. "
            "A higher absolute value indicates a more decisive separation from the boundary."
        ) if decision_score is not None else "ML classification completed."

        return MLResult(
            prediction=normalized,
            decision_score=decision_score,
            model_available=True,
            note=note,
        )

    except Exception as exc:
        return MLResult(
            prediction="UNKNOWN",
            decision_score=None,
            model_available=True,
            note=f"ML classification failed at runtime: {exc}",
        )
