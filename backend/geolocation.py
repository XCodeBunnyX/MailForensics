"""
GmailGuard — Geolocation Module

Maps observable public IP addresses to geographic and network context.
Supports two modes:
  - LIVE  (config.GEOLOCATION_LIVE = True):  calls ip-api.com REST API
  - MOCK  (config.GEOLOCATION_LIVE = False): returns mock/demo data

IMPORTANT FORENSIC NOTES:
  - Geolocation data represents the mail RELAY infrastructure location.
  - It does NOT represent the sender's physical location.
  - If geolocation is unavailable, UNKNOWN is returned — never fabricated.
  - Geolocation has limited direct influence on threat score;
    it is primarily FORENSIC CONTEXT.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional

import config

# ── Mock geolocation database ───────────────────────────────────
# Keyed by IP address.  None values → UNKNOWN.
_MOCK_GEO_DB: dict[str, dict] = {
    "185.234.219.47": {
        "country": "Russia", "region": "Moscow Oblast", "city": "Moscow",
        "lat": 55.7558, "lon": 37.6173,
        "asn": "AS206728", "isp": "Media Land LLC", "org": "Media Land LLC",
    },
    "45.141.86.100": {
        "country": "Netherlands", "region": "North Holland", "city": "Amsterdam",
        "lat": 52.3676, "lon": 4.9041,
        "asn": "AS9009", "isp": "M247 Ltd", "org": "M247 Ltd",
    },
    "91.219.236.14": {
        "country": "Ukraine", "region": "Kyiv Oblast", "city": "Kyiv",
        "lat": 50.4501, "lon": 30.5234,
        "asn": "AS196695", "isp": "OOO Network of data-centers",
        "org": "OOO Network of data-centers",
    },
    "103.21.244.0": {
        "country": "India", "region": "Maharashtra", "city": "Mumbai",
        "lat": 19.0760, "lon": 72.8777,
        "asn": "AS13335", "isp": "Cloudflare India", "org": "Cloudflare, Inc.",
    },
    "194.165.16.78": {
        "country": "Moldova", "region": "Chișinău", "city": "Chisinau",
        "lat": 47.0105, "lon": 28.8638,
        "asn": "AS198385", "isp": "AlexHost SRL", "org": "AlexHost SRL",
    },
    "8.8.8.8": {
        "country": "United States", "region": "California", "city": "Mountain View",
        "lat": 37.3861, "lon": -122.0839,
        "asn": "AS15169", "isp": "Google LLC", "org": "Google LLC",
    },
    "74.125.200.27": {
        "country": "United States", "region": "California", "city": "Mountain View",
        "lat": 37.3861, "lon": -122.0839,
        "asn": "AS15169", "isp": "Google LLC", "org": "Google LLC",
    },
}

_UNKNOWN_GEO: dict = {
    "country": "UNKNOWN", "region": "UNKNOWN", "city": "UNKNOWN",
    "lat": None, "lon": None,
    "asn": "UNKNOWN", "isp": "UNKNOWN", "org": "UNKNOWN",
}


@dataclass
class GeoRecord:
    """Geolocation record for a single IP address."""
    ip: str
    country: str
    region: str
    city: str
    lat: Optional[float]
    lon: Optional[float]
    asn: str
    isp: str
    org: str
    source: str           # "LIVE_API" | "MOCK" | "UNAVAILABLE"
    forensic_note: str    # always reminds analyst this is relay infra


def _geo_from_dict(ip: str, data: dict, source: str) -> GeoRecord:
    return GeoRecord(
        ip=ip,
        country=data.get("country", "UNKNOWN") or "UNKNOWN",
        region=data.get("region", "UNKNOWN") or "UNKNOWN",
        city=data.get("city", "UNKNOWN") or "UNKNOWN",
        lat=data.get("lat"),
        lon=data.get("lon"),
        asn=data.get("asn", "UNKNOWN") or "UNKNOWN",
        isp=data.get("isp", "UNKNOWN") or "UNKNOWN",
        org=data.get("org", "UNKNOWN") or "UNKNOWN",
        source=source,
        forensic_note=(
            f"IP {ip} is an observable mail relay address — "
            "its geographic location indicates relay infrastructure, "
            "NOT the sender's physical location."
        ),
    )


def _geolocate_live(ip: str) -> GeoRecord:
    """Call ip-api.com for live geolocation. Falls back to UNKNOWN on error."""
    url = config.GEOLOCATION_API_URL.format(ip=ip)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GmailGuard/1.0"})
        with urllib.request.urlopen(req, timeout=config.GEOLOCATION_TIMEOUT_S) as resp:
            raw = resp.read().decode("utf-8")
            data = json.loads(raw)
            if data.get("status") == "success":
                mapped = {
                    "country": data.get("country"),
                    "region":  data.get("regionName"),
                    "city":    data.get("city"),
                    "lat":     data.get("lat"),
                    "lon":     data.get("lon"),
                    "asn":     data.get("as"),
                    "isp":     data.get("isp"),
                    "org":     data.get("org"),
                }
                return _geo_from_dict(ip, mapped, source="LIVE_API")
    except (urllib.error.URLError, json.JSONDecodeError, Exception):
        pass   # Silently fall through to UNKNOWN

    return _geo_from_dict(ip, _UNKNOWN_GEO, source="UNAVAILABLE")


def _geolocate_mock(ip: str) -> GeoRecord:
    """Return mock geolocation data, or UNKNOWN if not in mock DB."""
    data = _MOCK_GEO_DB.get(ip, _UNKNOWN_GEO)
    source = "MOCK" if ip in _MOCK_GEO_DB else "UNAVAILABLE"
    return _geo_from_dict(ip, data, source=source)


def geolocate_ips(ip_list: list[str]) -> list[GeoRecord]:
    """
    Geolocate a list of public IP addresses.

    Args:
        ip_list: Public IP addresses extracted from email headers.

    Returns:
        List of GeoRecord objects. Empty list if ip_list is empty.
    """
    records: list[GeoRecord] = []
    for ip in ip_list:
        if config.GEOLOCATION_LIVE:
            records.append(_geolocate_live(ip))
        else:
            records.append(_geolocate_mock(ip))
    return records
