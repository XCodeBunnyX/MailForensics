"""
GmailGuard — Mock IP Reputation Database

This is MOCK/DEMO data only.
In production, replace get_ip_reputation() with a real provider
(VirusTotal, AbuseIPDB, Shodan, etc.).

NEVER treat mock results as real threat intelligence.
"""

from __future__ import annotations

# Mock reputation entries keyed by IP address.
# Fields:
#   reputation : "malicious" | "suspicious" | "clean" | "unknown"
#   score      : 0-100  (higher = more malicious)
#   categories : list of threat category labels
#   source     : mock provider label
_MOCK_IP_DB: dict[str, dict] = {
    "185.234.219.47": {
        "reputation": "malicious",
        "score": 95,
        "categories": ["Phishing Host", "Bulletproof Hosting"],
        "source": "MOCK_INTEL",
    },
    "45.141.86.100": {
        "reputation": "suspicious",
        "score": 72,
        "categories": ["BEC Infrastructure", "Spam Source"],
        "source": "MOCK_INTEL",
    },
    "91.219.236.14": {
        "reputation": "malicious",
        "score": 90,
        "categories": ["Malware Hosting", "C2 Infrastructure"],
        "source": "MOCK_INTEL",
    },
    "103.21.244.0": {
        "reputation": "clean",
        "score": 5,
        "categories": [],
        "source": "MOCK_INTEL",
    },
    "194.165.16.78": {
        "reputation": "malicious",
        "score": 88,
        "categories": ["Phishing Host", "Spam"],
        "source": "MOCK_INTEL",
    },
    "8.8.8.8": {
        "reputation": "clean",
        "score": 0,
        "categories": [],
        "source": "MOCK_INTEL",
    },
    "74.125.200.27": {
        "reputation": "clean",
        "score": 2,
        "categories": [],
        "source": "MOCK_INTEL",
    },
}

_UNKNOWN_REPUTATION: dict = {
    "reputation": "unknown",
    "score": 50,      # neutral — unknown ≠ malicious
    "categories": [],
    "source": "MOCK_INTEL",
}


def get_ip_reputation(ip: str) -> dict:
    """
    Return mock reputation data for an IP address.

    In production replace this function body with a real API call.
    The return contract (keys: reputation, score, categories, source)
    must be preserved so callers don't need to change.

    Args:
        ip: The IP address string to look up.

    Returns:
        A dict with keys: reputation, score, categories, source.
        Unknown IPs return a neutral (score=50, reputation='unknown') result.
    """
    return _MOCK_IP_DB.get(ip, dict(_UNKNOWN_REPUTATION))
