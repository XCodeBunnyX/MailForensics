"""
GmailGuard — Geolocation & IPinfo Integration Module

Maps observable public IP addresses to geographic and network context using IPinfo.
Primary forensic objective:
  - Geolocation identifies observable mail relay infrastructure location.
  - It does NOT represent the sender's physical location.
  - Missing or unconfigured fields are reported as UNKNOWN / UNAVAILABLE — never fabricated.
  - Geolocation provides contextual evidence and does not inflate malicious threat scores.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

import config

# ── In-memory session cache ──────────────────────────────────────
# Caches IP lookups during email analysis to prevent duplicate API requests.
_GEO_CACHE: dict[str, dict[str, Any]] = {}

LOCATION_TYPE_INFRASTRUCTURE = "observable_infrastructure"
LOCATION_DISCLAIMER = (
    "IP geolocation represents the approximate location of the observed "
    "network infrastructure and may not represent the sender's physical location."
)


def clear_geo_cache() -> None:
    """Clear in-memory geolocation cache (useful for testing)."""
    _GEO_CACHE.clear()


@dataclass
class GeoRecord:
    """Geolocation record for a single IP address."""
    ip: str
    country: str = "UNKNOWN"
    region: str = "UNKNOWN"
    city: str = "UNKNOWN"
    lat: Optional[float] = None
    lon: Optional[float] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    postal: Optional[str] = None
    timezone: Optional[str] = None
    asn: str = "UNKNOWN"
    isp: str = "UNKNOWN"
    org: str = "UNKNOWN"
    organization: Optional[str] = None
    hostname: Optional[str] = None
    network: Optional[str] = None
    source: str = "IPinfo"
    status: str = "success"  # "success" | "unavailable" | "rejected" | "error"
    reason: Optional[str] = None
    location_type: str = LOCATION_TYPE_INFRASTRUCTURE
    location_note: str = LOCATION_DISCLAIMER
    forensic_note: str = LOCATION_DISCLAIMER

    def __post_init__(self) -> None:
        if self.latitude is None and self.lat is not None:
            self.latitude = self.lat
        elif self.lat is None and self.latitude is not None:
            self.lat = self.latitude

        if self.longitude is None and self.lon is not None:
            self.longitude = self.lon
        elif self.lon is None and self.longitude is not None:
            self.lon = self.longitude

        if not self.organization and self.org != "UNKNOWN":
            self.organization = self.org
        elif not self.org and self.organization:
            self.org = self.organization

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ip": self.ip,
            "country": self.country,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "lat": self.lat,
            "lon": self.lon,
            "postal": self.postal,
            "timezone": self.timezone,
            "asn": self.asn,
            "organization": self.organization or self.org,
            "isp": self.isp,
            "org": self.org,
            "hostname": self.hostname,
            "network": self.network,
            "source": self.source,
            "status": self.status,
            "location_type": self.location_type,
            "location_note": self.location_note,
            "forensic_note": self.forensic_note,
        }
        if self.reason:
            d["reason"] = self.reason
        return d


def is_public_ip(ip: str) -> bool:
    """
    Validate that an IP string is a valid, publicly routable IP address.
    Rejects private, loopback, link-local, multicast, and reserved addresses.
    """
    if not ip or not isinstance(ip, str):
        return False
    clean_ip = ip.strip()
    try:
        addr = ipaddress.ip_address(clean_ip)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_link_local
            or addr.is_unspecified
        ):
            return False

        # Verify against configured private/reserved CIDRs
        if hasattr(config, "PRIVATE_IP_NETWORKS"):
            for cidr in config.PRIVATE_IP_NETWORKS:
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        return False
                except ValueError:
                    pass

        return True
    except ValueError:
        return False


def _is_valid_ip_format(ip: str) -> bool:
    """Return True if string can be parsed as IPv4 or IPv6."""
    if not ip or not isinstance(ip, str):
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def _build_forensic_note(ip: str, city: str, region: str, country: str) -> str:
    """Build standardized, objective forensic location note."""
    loc_parts = [p for p in [city, region, country] if p and p != "UNKNOWN"]
    loc_desc = ", ".join(loc_parts) if loc_parts else "an approximate location"
    return (
        f"Observed mail infrastructure is geolocated to {loc_desc}. "
        f"{LOCATION_DISCLAIMER}"
    )


def get_ip_geolocation(ip: str) -> dict[str, Any]:
    """
    Accept a public IP address and query IPinfo's API for geolocation and network context.

    Returns a structured dictionary:
      - Valid public IP with token -> status: "success", normalized fields
      - Missing token              -> status: "unavailable", reason: "IPinfo API token is not configured"
      - Private/reserved IP        -> status: "rejected", reason: "Private or reserved IP address"
      - Invalid IP format          -> status: "error", reason: "Invalid IP address format"
      - Network/API errors         -> status: "unavailable" or "error", descriptive reason
    """
    if not ip or not isinstance(ip, str):
        return {
            "ip": str(ip) if ip is not None else "",
            "status": "error",
            "reason": "Invalid IP address format",
            "source": "IPinfo",
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "latitude": None,
            "longitude": None,
            "asn": "UNKNOWN",
            "organization": "UNKNOWN",
            "location_type": LOCATION_TYPE_INFRASTRUCTURE,
            "location_note": LOCATION_DISCLAIMER,
        }

    clean_ip = ip.strip()

    # 1. Check in-memory cache
    if clean_ip in _GEO_CACHE:
        return dict(_GEO_CACHE[clean_ip])

    # 2. Validate IP format
    if not _is_valid_ip_format(clean_ip):
        result = {
            "ip": clean_ip,
            "status": "error",
            "reason": "Invalid IP address format",
            "source": "IPinfo",
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "latitude": None,
            "longitude": None,
            "asn": "UNKNOWN",
            "organization": "UNKNOWN",
            "location_type": LOCATION_TYPE_INFRASTRUCTURE,
            "location_note": LOCATION_DISCLAIMER,
        }
        return result

    # 3. Filter private, loopback, and reserved IPs
    if not is_public_ip(clean_ip):
        result = {
            "ip": clean_ip,
            "status": "rejected",
            "reason": "Private or reserved IP address",
            "source": "IPinfo",
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "latitude": None,
            "longitude": None,
            "asn": "UNKNOWN",
            "organization": "UNKNOWN",
            "location_type": LOCATION_TYPE_INFRASTRUCTURE,
            "location_note": LOCATION_DISCLAIMER,
        }
        return result

    # 4. Check IPinfo API Token
    token = (getattr(config, "IPINFO_TOKEN", None) or os.getenv("IPINFO_TOKEN", "")).strip()
    if not token:
        result = {
            "ip": clean_ip,
            "status": "unavailable",
            "reason": "IPinfo API token is not configured",
            "source": "IPinfo",
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "latitude": None,
            "longitude": None,
            "asn": "UNKNOWN",
            "organization": "UNKNOWN",
            "location_type": LOCATION_TYPE_INFRASTRUCTURE,
            "location_note": LOCATION_DISCLAIMER,
        }
        _GEO_CACHE[clean_ip] = result
        return dict(result)

    # 5. Query IPinfo API
    api_url = getattr(config, "IPINFO_API_URL", "https://ipinfo.io/{ip}/json").format(ip=clean_ip)
    timeout = int(getattr(config, "IPINFO_TIMEOUT_S", 5))

    req = urllib.request.Request(
        api_url,
        headers={
            "User-Agent": "GmailGuard/1.0",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)

        country = data.get("country") or "UNKNOWN"
        region = data.get("region") or "UNKNOWN"
        city = data.get("city") or "UNKNOWN"
        postal = data.get("postal") or None
        timezone = data.get("timezone") or None
        hostname = data.get("hostname") or None
        network = data.get("network") or data.get("bogon") or None

        # Coordinates from "loc" ("lat,lon")
        lat: Optional[float] = None
        lon: Optional[float] = None
        loc_val = data.get("loc")
        if loc_val and isinstance(loc_val, str) and "," in loc_val:
            try:
                parts = loc_val.split(",", 1)
                lat = float(parts[0].strip())
                lon = float(parts[1].strip())
            except (ValueError, TypeError):
                lat = None
                lon = None

        # ASN and Organization parsing
        raw_org = data.get("org") or ""
        asn = "UNKNOWN"
        organization = "UNKNOWN"

        if isinstance(data.get("asn"), dict):
            asn = data["asn"].get("asn") or "UNKNOWN"
            organization = data["asn"].get("name") or raw_org or "UNKNOWN"
        elif data.get("asn"):
            asn = str(data["asn"])
            organization = raw_org or "UNKNOWN"
        elif raw_org.startswith("AS") and " " in raw_org:
            parts = raw_org.split(" ", 1)
            asn = parts[0]
            organization = parts[1].strip()
        elif raw_org:
            organization = raw_org

        isp = data.get("isp") or organization or "UNKNOWN"

        forensic_note = _build_forensic_note(clean_ip, city, region, country)

        result = {
            "ip": clean_ip,
            "country": country,
            "region": region,
            "city": city,
            "latitude": lat,
            "longitude": lon,
            "lat": lat,
            "lon": lon,
            "postal": postal,
            "timezone": timezone,
            "asn": asn,
            "organization": organization,
            "isp": isp,
            "org": organization,
            "hostname": hostname,
            "network": network,
            "source": "IPinfo",
            "status": "success",
            "location_type": LOCATION_TYPE_INFRASTRUCTURE,
            "location_note": LOCATION_DISCLAIMER,
            "forensic_note": forensic_note,
        }

        _GEO_CACHE[clean_ip] = result
        return dict(result)

    except urllib.error.HTTPError as e:
        status = "unavailable" if e.code == 429 else "error"
        if e.code in (401, 403):
            reason = "IPinfo API authentication failed (invalid or unauthorized token)"
        elif e.code == 429:
            reason = "IPinfo API rate limit exceeded"
        else:
            reason = f"IPinfo API HTTP error {e.code}"

        result = {
            "ip": clean_ip,
            "status": status,
            "reason": reason,
            "source": "IPinfo",
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "latitude": None,
            "longitude": None,
            "asn": "UNKNOWN",
            "organization": "UNKNOWN",
            "location_type": LOCATION_TYPE_INFRASTRUCTURE,
            "location_note": LOCATION_DISCLAIMER,
        }
        _GEO_CACHE[clean_ip] = result
        return dict(result)

    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        reason = "IPinfo API request timed out"
        if isinstance(e, urllib.error.URLError) and not isinstance(e.reason, socket.timeout):
            reason_str = str(e.reason)
            if "timed out" in reason_str.lower():
                reason = "IPinfo API request timed out"
            else:
                reason = "IPinfo network connection unavailable"

        result = {
            "ip": clean_ip,
            "status": "unavailable",
            "reason": reason,
            "source": "IPinfo",
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "latitude": None,
            "longitude": None,
            "asn": "UNKNOWN",
            "organization": "UNKNOWN",
            "location_type": LOCATION_TYPE_INFRASTRUCTURE,
            "location_note": LOCATION_DISCLAIMER,
        }
        _GEO_CACHE[clean_ip] = result
        return dict(result)

    except json.JSONDecodeError:
        result = {
            "ip": clean_ip,
            "status": "error",
            "reason": "Invalid JSON response from IPinfo",
            "source": "IPinfo",
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "latitude": None,
            "longitude": None,
            "asn": "UNKNOWN",
            "organization": "UNKNOWN",
            "location_type": LOCATION_TYPE_INFRASTRUCTURE,
            "location_note": LOCATION_DISCLAIMER,
        }
        _GEO_CACHE[clean_ip] = result
        return dict(result)

    except Exception as e:
        result = {
            "ip": clean_ip,
            "status": "error",
            "reason": f"IPinfo query failed: {type(e).__name__}",
            "source": "IPinfo",
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "latitude": None,
            "longitude": None,
            "asn": "UNKNOWN",
            "organization": "UNKNOWN",
            "location_type": LOCATION_TYPE_INFRASTRUCTURE,
            "location_note": LOCATION_DISCLAIMER,
        }
        _GEO_CACHE[clean_ip] = result
        return dict(result)


def get_ip_geolocation_record(ip: str) -> GeoRecord:
    """Return a GeoRecord object for an IP using IPinfo."""
    data = get_ip_geolocation(ip)
    return GeoRecord(
        ip=data.get("ip", ip),
        country=data.get("country", "UNKNOWN") or "UNKNOWN",
        region=data.get("region", "UNKNOWN") or "UNKNOWN",
        city=data.get("city", "UNKNOWN") or "UNKNOWN",
        lat=data.get("latitude") or data.get("lat"),
        lon=data.get("longitude") or data.get("lon"),
        latitude=data.get("latitude") or data.get("lat"),
        longitude=data.get("longitude") or data.get("lon"),
        postal=data.get("postal"),
        timezone=data.get("timezone"),
        asn=data.get("asn", "UNKNOWN") or "UNKNOWN",
        isp=data.get("isp", "UNKNOWN") or "UNKNOWN",
        org=data.get("organization") or data.get("org", "UNKNOWN") or "UNKNOWN",
        organization=data.get("organization"),
        hostname=data.get("hostname"),
        network=data.get("network"),
        source=data.get("source", "IPinfo"),
        status=data.get("status", "success"),
        reason=data.get("reason"),
        location_type=data.get("location_type", LOCATION_TYPE_INFRASTRUCTURE),
        location_note=data.get("location_note", LOCATION_DISCLAIMER),
        forensic_note=data.get("forensic_note", LOCATION_DISCLAIMER),
    )


def geolocate_ips(ip_list: list[str]) -> list[GeoRecord]:
    """
    Geolocate a list of public IP addresses extracted from email headers.

    - Resolves each IP via get_ip_geolocation.
    - Utilizes in-memory session caching so duplicate IPs across the list
      are queried from the network at most once.
    - Preserves ordering and returns a list of GeoRecord objects.
    """
    records: list[GeoRecord] = []
    if not ip_list:
        return records

    for ip in ip_list:
        records.append(get_ip_geolocation_record(ip))

    return records
