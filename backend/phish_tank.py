"""
GmailGuard — PhishTank URL Intelligence

Checks URLs against the PhishTank database to determine whether
they are known/verified phishing URLs.

DESIGN RULES:
    - Passive API lookup only. NEVER visit, execute, or render URLs.
    - "Not found in PhishTank" does NOT mean the URL is safe.
    - API key is loaded from environment; missing key → graceful degradation.
    - Mock mode available for offline demos and testing.
    - Each unique URL is queried at most once per analysis run.
    - API keys are never logged or exposed in responses.

PROVIDERS:
    - MockPhishTankProvider   (deterministic demo data, always available)
    - LivePhishTankProvider   (requires PHISHTANK_API_KEY env var)
    - UnavailableProvider     (fallback when no key and mock mode off)
"""

from __future__ import annotations

import abc
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

import config


# ═══════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PhishTankResult:
    """Result of a PhishTank lookup for a single URL."""
    url: str
    in_database: bool
    verified: bool
    valid: bool
    phish_id: Optional[str]
    source: str                    # "PhishTank" | "Mock/Demo" | "Unavailable"
    error: Optional[str] = None   # Error message if lookup failed

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "url": self.url,
            "in_database": self.in_database,
            "verified": self.verified,
            "valid": self.valid,
            "phish_id": self.phish_id,
            "source": self.source,
        }
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class PhishTankAnalysis:
    """Aggregated PhishTank results for all URLs in an email."""
    results: list[PhishTankResult]
    verified_phishing_count: int
    source: str
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "results": [r.to_dict() for r in self.results],
            "verified_phishing_count": self.verified_phishing_count,
            "source": self.source,
            "limitations": self.limitations,
        }


# ═══════════════════════════════════════════════════════════════════
# PROVIDER ABSTRACTION
# ═══════════════════════════════════════════════════════════════════

class PhishTankProvider(abc.ABC):
    """Abstract interface for PhishTank intelligence providers."""

    @abc.abstractmethod
    def name(self) -> str: ...

    @abc.abstractmethod
    def check_url(self, url: str) -> PhishTankResult: ...


# ───────────────────────────────────────────────────────────────────
# 1. Mock Provider (Deterministic Demo)
# ───────────────────────────────────────────────────────────────────

# Known mock phishing URLs for demonstration
_MOCK_PHISHING_DB: dict[str, dict[str, Any]] = {
    "http://bit.ly/3xHDFC-verify": {
        "in_database": True,
        "verified": True,
        "valid": True,
        "phish_id": "8901234",
    },
    "http://hdfcbank-secure.co.in/login.php": {
        "in_database": True,
        "verified": True,
        "valid": True,
        "phish_id": "8901235",
    },
    "http://hdfc-secure-verify.co.in/login": {
        "in_database": True,
        "verified": True,
        "valid": True,
        "phish_id": "8901236",
    },
}


class MockPhishTankProvider(PhishTankProvider):
    """Deterministic mock provider for offline demo and testing."""

    def name(self) -> str:
        return "Mock/Demo"

    def check_url(self, url: str) -> PhishTankResult:
        # Exact match
        if url in _MOCK_PHISHING_DB:
            entry = _MOCK_PHISHING_DB[url]
            return PhishTankResult(
                url=url,
                in_database=entry["in_database"],
                verified=entry["verified"],
                valid=entry["valid"],
                phish_id=entry["phish_id"],
                source="Mock/Demo",
            )

        # Normalized match (strip trailing slash, query params)
        url_stripped = url.split("?")[0].rstrip("/")
        for k, v in _MOCK_PHISHING_DB.items():
            if k.split("?")[0].rstrip("/") == url_stripped:
                return PhishTankResult(
                    url=url,
                    in_database=v["in_database"],
                    verified=v["verified"],
                    valid=v["valid"],
                    phish_id=v["phish_id"],
                    source="Mock/Demo",
                )

        # Not found — does NOT mean safe
        return PhishTankResult(
            url=url,
            in_database=False,
            verified=False,
            valid=False,
            phish_id=None,
            source="Mock/Demo",
        )


# ───────────────────────────────────────────────────────────────────
# 2. Live PhishTank Provider
# ───────────────────────────────────────────────────────────────────

class LivePhishTankProvider(PhishTankProvider):
    """
    Live PhishTank API provider.
    Uses the PhishTank checkurl API endpoint.
    """

    ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self, api_key: str):
        self._api_key = api_key
        self._timeout = config.PHISHTANK_API_TIMEOUT_S

    def name(self) -> str:
        return "PhishTank"

    def check_url(self, url: str) -> PhishTankResult:
        try:
            post_data = urllib.parse.urlencode({
                "url": url,
                "format": "json",
                "app_key": self._api_key,
            }).encode("utf-8")

            req = urllib.request.Request(
                self.ENDPOINT,
                data=post_data,
                headers={
                    "User-Agent": "phishtank/GmailGuard",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            results = data.get("results", {})
            in_db = results.get("in_database", False)

            if in_db:
                return PhishTankResult(
                    url=url,
                    in_database=True,
                    verified=results.get("verified", False),
                    valid=results.get("valid", False),
                    phish_id=str(results.get("phish_id", "")),
                    source="PhishTank",
                )
            else:
                return PhishTankResult(
                    url=url,
                    in_database=False,
                    verified=False,
                    valid=False,
                    phish_id=None,
                    source="PhishTank",
                )

        except urllib.error.HTTPError as e:
            return PhishTankResult(
                url=url,
                in_database=False,
                verified=False,
                valid=False,
                phish_id=None,
                source="PhishTank",
                error=f"PhishTank API returned HTTP {e.code}",
            )
        except Exception as e:
            return PhishTankResult(
                url=url,
                in_database=False,
                verified=False,
                valid=False,
                phish_id=None,
                source="PhishTank",
                error=f"PhishTank lookup failed: {type(e).__name__}",
            )


# ───────────────────────────────────────────────────────────────────
# 3. Unavailable Provider (no key, mock mode off)
# ───────────────────────────────────────────────────────────────────

class UnavailablePhishTankProvider(PhishTankProvider):
    """Fallback when PhishTank is not configured."""

    def name(self) -> str:
        return "Unavailable"

    def check_url(self, url: str) -> PhishTankResult:
        return PhishTankResult(
            url=url,
            in_database=False,
            verified=False,
            valid=False,
            phish_id=None,
            source="Unavailable",
            error="PhishTank API key not configured.",
        )


# ═══════════════════════════════════════════════════════════════════
# FACTORY & ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

def get_phishtank_provider() -> PhishTankProvider:
    """
    Resolve the active PhishTank provider.
    Priority:
        1. MOCK_PHISHTANK=true (default) → MockPhishTankProvider
        2. PHISHTANK_API_KEY present     → LivePhishTankProvider
        3. Fallback                      → UnavailablePhishTankProvider
    """
    if config.MOCK_PHISHTANK:
        return MockPhishTankProvider()

    if config.PHISHTANK_API_KEY:
        return LivePhishTankProvider(config.PHISHTANK_API_KEY)

    return UnavailablePhishTankProvider()


def check_urls_phishtank(
    urls: list[str],
    provider: Optional[PhishTankProvider] = None,
) -> PhishTankAnalysis:
    """
    Check a list of URLs against PhishTank.
    Deduplicates URLs so each is queried at most once.

    Args:
        urls: List of URL strings to check.
        provider: Optional provider override (for testing).

    Returns:
        PhishTankAnalysis with per-URL results.
    """
    active_provider = provider or get_phishtank_provider()
    provider_name = active_provider.name()

    results: list[PhishTankResult] = []
    seen: set[str] = set()
    limitations: list[str] = []

    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)

        result = active_provider.check_url(url)
        results.append(result)

        if result.error:
            limitations.append(result.error)

    verified_count = sum(1 for r in results if r.verified and r.valid)

    # Deduplicate limitations
    unique_limitations = list(dict.fromkeys(limitations))

    if provider_name == "Unavailable":
        unique_limitations.insert(0, "PhishTank intelligence is not available (API key not configured).")

    return PhishTankAnalysis(
        results=results,
        verified_phishing_count=verified_count,
        source=provider_name,
        limitations=unique_limitations,
    )
