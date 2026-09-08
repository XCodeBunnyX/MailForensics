"""
GmailGuard — OSINT Intelligence: Mock/Demo Data

Provides deterministic mock data for OSINT investigations (IPs, URLs, Domains).
Every record is explicitly stamped with "data_source": "Mock/Demo".

NEVER present this data as real threat intelligence.
"""

from __future__ import annotations
from typing import Any

# ── Mock IP Intelligence Database ─────────────────────────────────
MOCK_IP_OSINT_DB: dict[str, dict[str, Any]] = {
    "185.234.219.47": {
        "indicator": "185.234.219.47",
        "indicator_type": "ip",
        "data_source": "Mock/Demo",
        "current_information": {
            "reverse_dns": "mail-relay47.bulletproof-host.xyz",
            "asn": "AS64496",
            "isp": "Bulletproof Hosting Ltd",
            "org": "AS64496 Bulletproof Networks",
            "country": "Russia",
            "city": "Moscow",
            "reputation": "suspicious",
        },
        "historical_information": {
            "dns": [],
            "ips": [],
            "nameservers": [],
            "whois": [],
            "historical_hostnames": [
                {"hostname": "srv1.fast-hosting.ru", "first_seen": "2025-06-01", "last_seen": "2026-01-15"}
            ],
        },
        "security_observations": [
            {
                "date": "2026-08-20",
                "category": "Observed Mail Infrastructure in Phishing Campaign",
                "provider": "Mock/Demo",
                "finding": "Previously reported in credential harvesting email distribution.",
            },
            {
                "date": "2026-09-01",
                "category": "Observable High-Volume Spam Source",
                "provider": "Mock/Demo",
                "finding": "Security observation detected: listed by multiple DNSBLs.",
            },
        ],
        "related_infrastructure": [
            {
                "relationship": "Same IP observed hosting other domains",
                "target": "login-verify-account.top",
                "source": "Mock/Demo",
            },
            {
                "relationship": "Same ASN/Network provider",
                "target": "AS64496 (Bulletproof Hosting Ltd)",
                "source": "Mock/Demo",
            },
        ],
        "timeline": [
            {
                "date": "2025-06-01",
                "event": "Hostname Observed",
                "value": "srv1.fast-hosting.ru",
                "source": "Mock/Demo",
            },
            {
                "date": "2026-08-20",
                "event": "Security observation detected",
                "value": "Reported in phishing campaign",
                "source": "Mock/Demo",
            },
            {
                "date": "2026-09-01",
                "event": "Reverse DNS Updated",
                "value": "mail-relay47.bulletproof-host.xyz",
                "source": "Mock/Demo",
            },
        ],
        "evidence": [
            {
                "source": "OSINT/IP",
                "finding": "Observable mail infrastructure IP is hosted on known bulletproof provider.",
                "severity": "medium",
            },
            {
                "source": "OSINT/IP",
                "finding": "Previous security observations detected in spam/phishing distributions.",
                "severity": "medium",
            },
        ],
        "limitations": [],
    },
    "91.219.236.14": {
        "indicator": "91.219.236.14",
        "indicator_type": "ip",
        "data_source": "Mock/Demo",
        "current_information": {
            "reverse_dns": "vps-node14.offshore-vps.su",
            "asn": "AS58061",
            "isp": "Offshore VPS Network",
            "org": "Offshore VPS",
            "country": "Seychelles",
            "city": "Victoria",
            "reputation": "suspicious",
        },
        "historical_information": {
            "dns": [],
            "ips": [],
            "nameservers": [],
            "whois": [],
            "historical_hostnames": [],
        },
        "security_observations": [
            {
                "date": "2026-08-12",
                "category": "Malicious Host",
                "provider": "Mock/Demo",
                "finding": "Security observation detected by passive DNS sensors.",
            }
        ],
        "related_infrastructure": [
            {
                "relationship": "Same infrastructure provider",
                "target": "AS58061",
                "source": "Mock/Demo",
            }
        ],
        "timeline": [
            {
                "date": "2026-08-12",
                "event": "Security observation detected",
                "value": "Observed hosting unauthorized banking portal",
                "source": "Mock/Demo",
            }
        ],
        "evidence": [
            {
                "source": "OSINT/IP",
                "finding": "Observed IP has previous security observations from passive sensors.",
                "severity": "medium",
            }
        ],
        "limitations": [],
    },
    "45.141.86.100": {
        "indicator": "45.141.86.100",
        "indicator_type": "ip",
        "data_source": "Mock/Demo",
        "current_information": {
            "reverse_dns": "node100.anon-cloud.is",
            "asn": "AS49981",
            "isp": "AnonCloud Hosting",
            "org": "AnonCloud Infrastructure",
            "country": "Iceland",
            "city": "Reykjavik",
            "reputation": "neutral",
        },
        "historical_information": {
            "dns": [],
            "ips": [],
            "nameservers": [],
            "whois": [],
            "historical_hostnames": [],
        },
        "security_observations": [],
        "related_infrastructure": [],
        "timeline": [],
        "evidence": [],
        "limitations": [],
    },
    "209.85.220.41": {
        "indicator": "209.85.220.41",
        "indicator_type": "ip",
        "data_source": "Mock/Demo",
        "current_information": {
            "reverse_dns": "mail-sor-f41.google.com",
            "asn": "AS15169",
            "isp": "Google LLC",
            "org": "Google LLC",
            "country": "United States",
            "city": "Mountain View",
            "reputation": "clean",
        },
        "historical_information": {
            "dns": [],
            "ips": [],
            "nameservers": [],
            "whois": [],
            "historical_hostnames": [],
        },
        "security_observations": [],
        "related_infrastructure": [
            {
                "relationship": "Same infrastructure provider",
                "target": "AS15169 (Google LLC)",
                "source": "Mock/Demo",
            }
        ],
        "timeline": [],
        "evidence": [
            {
                "source": "OSINT/IP",
                "finding": "Observed mail infrastructure is verified Google outbound relay.",
                "severity": "low",
            }
        ],
        "limitations": [],
    },
}

# ── Mock URL Intelligence Database ────────────────────────────────
MOCK_URL_OSINT_DB: dict[str, dict[str, Any]] = {
    "http://bit.ly/3xHDFC-verify": {
        "indicator": "http://bit.ly/3xHDFC-verify",
        "indicator_type": "url",
        "data_source": "Mock/Demo",
        "current_information": {
            "domain": "bit.ly",
            "reputation": "suspicious",
            "detection_count": 4,
            "total_engines": 72,
            "categories": ["URL Shortener", "Potential Phishing Redirect"],
        },
        "historical_information": {
            "dns": [],
            "ips": [],
            "nameservers": [],
            "whois": [],
        },
        "security_observations": [
            {
                "date": "2026-09-02",
                "category": "Phishing Redirect",
                "provider": "Mock/Demo",
                "finding": "Previously reported URL masking destination hdfcbank-secure.co.in",
            }
        ],
        "related_infrastructure": [
            {
                "relationship": "Target redirect domain observed",
                "target": "hdfcbank-secure.co.in",
                "source": "Mock/Demo",
            }
        ],
        "timeline": [
            {
                "date": "2026-09-02",
                "event": "Security observation detected",
                "value": "Reported as phishing redirect masking destination",
                "source": "Mock/Demo",
            }
        ],
        "evidence": [
            {
                "source": "OSINT/URL",
                "finding": "URL shortener mask detected with previous security observations.",
                "severity": "high",
            }
        ],
        "limitations": [
            "Passive analysis only: Live HTTP redirection was not traversed to prevent payload execution."
        ],
    },
    "http://hdfcbank-secure.co.in/login.php": {
        "indicator": "http://hdfcbank-secure.co.in/login.php",
        "indicator_type": "url",
        "data_source": "Mock/Demo",
        "current_information": {
            "domain": "hdfcbank-secure.co.in",
            "reputation": "suspicious",
            "detection_count": 8,
            "total_engines": 74,
            "categories": ["Phishing", "Financial Brand Impersonation"],
        },
        "historical_information": {
            "dns": [],
            "ips": [],
            "nameservers": [],
            "whois": [],
        },
        "security_observations": [
            {
                "date": "2026-09-01",
                "category": "Credential Harvesting",
                "provider": "Mock/Demo",
                "finding": "Security observation detected by multiple anti-phishing feeds.",
            }
        ],
        "related_infrastructure": [
            {
                "relationship": "Hosting domain",
                "target": "hdfcbank-secure.co.in",
                "source": "Mock/Demo",
            }
        ],
        "timeline": [
            {
                "date": "2026-09-01",
                "event": "Security observation detected",
                "value": "Flagged as fake bank credential harvester",
                "source": "Mock/Demo",
            }
        ],
        "evidence": [
            {
                "source": "OSINT/URL",
                "finding": "URL has 8 security vendor detections for credential phishing.",
                "severity": "high",
            }
        ],
        "limitations": [],
    },
}


def get_mock_ip_osint(ip: str) -> tuple[dict[str, Any], bool]:
    """Retrieve mock OSINT data for an IP address."""
    if ip in MOCK_IP_OSINT_DB:
        return dict(MOCK_IP_OSINT_DB[ip]), True

    # Fallback generic record for any unlisted IP
    return {
        "indicator": ip,
        "indicator_type": "ip",
        "data_source": "Mock/Demo",
        "current_information": {
            "reverse_dns": "None",
            "asn": "AS0",
            "isp": "Demonstration Network Provider",
            "org": "Demonstration Network",
            "country": "Unknown",
            "city": "Unknown",
            "reputation": "unknown",
        },
        "historical_information": {
            "dns": [],
            "ips": [],
            "nameservers": [],
            "whois": [],
            "historical_hostnames": [],
        },
        "security_observations": [],
        "related_infrastructure": [],
        "timeline": [],
        "evidence": [],
        "limitations": ["Indicator has no prior entries in demonstration database."],
    }, False


def get_mock_url_osint(url: str, domain: str = "") -> tuple[dict[str, Any], bool]:
    """Retrieve mock OSINT data for a URL."""
    if url in MOCK_URL_OSINT_DB:
        return dict(MOCK_URL_OSINT_DB[url]), True

    # Check normalized URL without trailing slash
    url_stripped = url.rstrip("/")
    for k, v in MOCK_URL_OSINT_DB.items():
        if k.rstrip("/") == url_stripped:
            return dict(v), True

    # Fallback generic URL record
    return {
        "indicator": url,
        "indicator_type": "url",
        "data_source": "Mock/Demo",
        "current_information": {
            "domain": domain,
            "reputation": "unknown",
            "detection_count": 0,
            "total_engines": 70,
            "categories": [],
        },
        "historical_information": {
            "dns": [],
            "ips": [],
            "nameservers": [],
            "whois": [],
        },
        "security_observations": [],
        "related_infrastructure": [],
        "timeline": [],
        "evidence": [],
        "limitations": ["No security observations reported in demo database for this URL."],
    }, False
