"""
Pytest configuration for GmailGuard test suite.

Ensures automated tests do NOT hit real external APIs (urlscan.io, IPinfo)
repeatedly, adhering to test best practices and requirement 14.
"""

import pytest
from .. import config


@pytest.fixture(autouse=True)
def default_mock_for_automated_tests(monkeypatch):
    """
    Default to mock mode during test suite runs to prevent uncontrolled
    external network requests and rate limiting.
    Tests specifically testing live mode or API errors use patch.object(config, 'MOCK_URLSCAN', False).
    """
    monkeypatch.setattr(config, "MOCK_URLSCAN", True)
