"""
GmailGuard — Mock Domain Reputation Database

This is MOCK/DEMO data only.
In production, replace get_domain_reputation() with a real provider
(VirusTotal, Whois, URLhaus, etc.).

NEVER treat mock results as real threat intelligence.
"""

from __future__ import annotations
import re

# Mock domain reputation entries.
# Fields:
#   reputation       : "malicious" | "suspicious" | "clean" | "unknown"
#   score            : 0-100
#   categories       : list of threat category labels
#   age_days         : domain age in days (None = unknown)
#   registrar        : registrar name (None = unknown)
#   virustotal_flags : number of VT engines flagging (None = not checked)
#   source           : provider label
_MOCK_DOMAIN_DB: dict[str, dict] = {
    "hdfcbank-secure.co.in": {
        "reputation": "malicious",
        "score": 95,
        "categories": ["Typosquatting", "Brand Impersonation", "Phishing"],
        "age_days": 19,
        "registrar": "GoDaddy LLC",
        "virustotal_flags": 41,
        "source": "MOCK_INTEL",
    },
    "company-corp.net": {
        "reputation": "suspicious",
        "score": 65,
        "categories": ["Newly Registered", "BEC Infrastructure"],
        "age_days": 43,
        "registrar": "Namecheap Inc",
        "virustotal_flags": 18,
        "source": "MOCK_INTEL",
    },
    "invoices-portal.xyz": {
        "reputation": "suspicious",
        "score": 70,
        "categories": ["Generic Name", "Malware Hosting"],
        "age_days": 85,
        "registrar": "Tucows Inc",
        "virustotal_flags": 22,
        "source": "MOCK_INTEL",
    },
    "hdfc-secure-verify.co.in": {
        "reputation": "malicious",
        "score": 93,
        "categories": ["Typosquatting", "Phishing"],
        "age_days": 14,
        "registrar": "BigRock",
        "virustotal_flags": 38,
        "source": "MOCK_INTEL",
    },
    "paypal-update.support": {
        "reputation": "malicious",
        "score": 90,
        "categories": ["Brand Impersonation", "Phishing"],
        "age_days": 30,
        "registrar": "Namecheap Inc",
        "virustotal_flags": 35,
        "source": "MOCK_INTEL",
    },
    "gmail.com": {
        "reputation": "clean",
        "score": 0,
        "categories": [],
        "age_days": 9131,
        "registrar": "MarkMonitor Inc.",
        "virustotal_flags": 0,
        "source": "MOCK_INTEL",
    },
    "google.com": {
        "reputation": "clean",
        "score": 0,
        "categories": [],
        "age_days": 9862,
        "registrar": "MarkMonitor Inc.",
        "virustotal_flags": 0,
        "source": "MOCK_INTEL",
    },
}

_UNKNOWN_REPUTATION: dict = {
    "reputation": "unknown",
    "score": 50,      # neutral — unknown ≠ malicious
    "categories": [],
    "age_days": None,
    "registrar": None,
    "virustotal_flags": None,
    "source": "MOCK_INTEL",
}

# Suspicious TLD set for quick check (supplements main analysis)
_SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
    ".work", ".click", ".download", ".link", ".zip", ".mov",
}


def get_domain_reputation(domain: str) -> dict:
    """
    Return mock reputation data for a domain.

    In production replace this function body with a real API call.
    The return contract must be preserved.

    Args:
        domain: The domain name (e.g. 'example.com').

    Returns:
        A dict with keys: reputation, score, categories, age_days,
        registrar, virustotal_flags, source.
    """
    domain = domain.lower().strip()
    if domain in _MOCK_DOMAIN_DB:
        return dict(_MOCK_DOMAIN_DB[domain])

    # Heuristic check for clearly suspicious TLDs even if not in DB
    tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in _SUSPICIOUS_TLDS:
        return {
            "reputation": "suspicious",
            "score": 60,
            "categories": ["Suspicious TLD"],
            "age_days": None,
            "registrar": None,
            "virustotal_flags": None,
            "source": "MOCK_INTEL_HEURISTIC",
        }

    return dict(_UNKNOWN_REPUTATION)
