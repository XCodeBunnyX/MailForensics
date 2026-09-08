"""
GmailGuard — Forensic Domain Intelligence: Mock/Demo Data

This is DETERMINISTIC MOCK DATA for development and demonstration.
It is clearly labeled "Mock/Demo" in every response.

NEVER present this data as real threat intelligence.
It does not represent actual historical observations.
"""

from __future__ import annotations

# ── Mock forensic database ───────────────────────────────────────
# Each entry is keyed by domain and provides a complete forensic
# dataset matching the DomainForensicResult schema.
MOCK_FORENSIC_DB: dict[str, dict] = {
    "hdfcbank-secure.co.in": {
        "current_dns": {
            "A":     ["185.234.219.47"],
            "AAAA":  [],
            "MX":    [],
            "NS":    ["ns1.freenom.com", "ns2.freenom.com"],
            "CNAME": [],
            "TXT":   [],
        },
        "historical_dns": {
            "A": [
                {"value": "91.219.236.14", "first_seen": "2026-08-10", "last_seen": "2026-08-14"},
            ],
            "AAAA":  [],
            "MX":    [],
            "NS":    [],
            "CNAME": [],
        },
        "historical_ips": [
            {"ip": "91.219.236.14", "first_seen": "2026-08-10", "last_seen": "2026-08-14"},
            {"ip": "185.234.219.47", "first_seen": "2026-09-01", "last_seen": "2026-09-03"},
        ],
        "whois_history": [
            {
                "registrar": "GoDaddy LLC",
                "registered": "2026-08-15",
                "updated": "2026-08-15",
                "expires": "2027-08-15",
                "nameservers": ["ns1.freenom.com", "ns2.freenom.com"],
            }
        ],
        "security_history": {
            "previously_detected": True,
            "currently_detected": True,
            "detections": [
                {"date": "2026-08-20", "category": "Phishing", "provider": "Mock/Demo"},
                {"date": "2026-09-01", "category": "Brand Impersonation", "provider": "Mock/Demo"},
            ],
        },
    },
    "company-corp.net": {
        "current_dns": {
            "A":     ["45.141.86.100"],
            "AAAA":  [],
            "MX":    [{"priority": 10, "host": "mail.company-corp.net"}],
            "NS":    ["dns1.registrar-servers.com"],
            "CNAME": [],
            "TXT":   [],
        },
        "historical_dns": {
            "A":     [],
            "AAAA":  [],
            "MX":    [],
            "NS":    [],
            "CNAME": [],
        },
        "historical_ips": [
            {"ip": "45.141.86.100", "first_seen": "2026-07-22", "last_seen": "2026-09-03"},
        ],
        "whois_history": [
            {
                "registrar": "Namecheap Inc",
                "registered": "2026-07-22",
                "updated": "2026-07-22",
                "expires": "2027-07-22",
                "nameservers": ["dns1.registrar-servers.com"],
            }
        ],
        "security_history": {
            "previously_detected": False,
            "currently_detected": True,
            "detections": [
                {"date": "2026-09-03", "category": "BEC Infrastructure", "provider": "Mock/Demo"},
            ],
        },
    },
    "invoices-portal.xyz": {
        "current_dns": {
            "A":     ["91.219.236.14"],
            "AAAA":  [],
            "MX":    [],
            "NS":    ["ns1.parkingcrew.net"],
            "CNAME": [],
            "TXT":   [],
        },
        "historical_dns": {
            "A":     [{"value": "194.165.16.78", "first_seen": "2026-06-10", "last_seen": "2026-07-15"}],
            "AAAA":  [],
            "MX":    [],
            "NS":    [{"value": "ns1.old-provider.net", "first_seen": "2026-06-10", "last_seen": "2026-07-01"}],
            "CNAME": [],
        },
        "historical_ips": [
            {"ip": "194.165.16.78", "first_seen": "2026-06-10", "last_seen": "2026-07-15"},
            {"ip": "91.219.236.14", "first_seen": "2026-07-16", "last_seen": "2026-09-02"},
        ],
        "whois_history": [
            {
                "registrar": "Tucows Inc",
                "registered": "2026-06-10",
                "updated": "2026-07-02",
                "expires": "2027-06-10",
                "nameservers": ["ns1.parkingcrew.net"],
            }
        ],
        "security_history": {
            "previously_detected": True,
            "currently_detected": True,
            "detections": [
                {"date": "2026-07-20", "category": "Malware Hosting", "provider": "Mock/Demo"},
            ],
        },
    },
    "github.com": {
        "current_dns": {
            "A":     ["140.82.121.4"],
            "AAAA":  [],
            "MX":    [{"priority": 1, "host": "aspmx.l.google.com"}],
            "NS":    ["ns1.p16.dynect.net", "ns2.p16.dynect.net"],
            "CNAME": [],
            "TXT":   ["v=spf1 ip4:192.30.252.0/22 include:_netblocks.google.com ~all"],
        },
        "historical_dns": {
            "A":     [],
            "AAAA":  [],
            "MX":    [],
            "NS":    [],
            "CNAME": [],
        },
        "historical_ips": [
            {"ip": "140.82.121.4", "first_seen": "2020-01-01", "last_seen": "2026-09-07"},
        ],
        "whois_history": [
            {
                "registrar": "MarkMonitor Inc.",
                "registered": "2007-10-09",
                "updated": "2022-09-10",
                "expires": "2024-10-09",
                "nameservers": ["ns1.p16.dynect.net"],
            }
        ],
        "security_history": {
            "previously_detected": False,
            "currently_detected": False,
            "detections": [],
        },
    },
}

# Default response for domains not in mock DB
_DEFAULT_RESPONSE: dict = {
    "current_dns": {
        "A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": [], "TXT": [],
    },
    "historical_dns": {
        "A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": [],
    },
    "historical_ips":  [],
    "whois_history":   [],
    "security_history": {
        "previously_detected": False,
        "currently_detected":  False,
        "detections": [],
    },
}


def get_mock_forensic_data(domain: str) -> tuple[dict, bool]:
    """
    Return (mock_data_dict, found_in_db).

    If domain is not in the mock DB, returns a structured empty
    response — not an error, not fake data.
    """
    domain = domain.lower().strip()
    if domain in MOCK_FORENSIC_DB:
        import copy
        return copy.deepcopy(MOCK_FORENSIC_DB[domain]), True
    return dict(_DEFAULT_RESPONSE), False
