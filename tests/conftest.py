from __future__ import annotations

import pytest

from phishing_scanner.scanner import PhishingScanner
from phishing_scanner.threat_intel import ThreatIntel


@pytest.fixture
def threat_intel() -> ThreatIntel:
    return ThreatIntel(
        malicious_domains=frozenset({"evil-bank-login.xyz", "totally-not-paypal.com"}),
        malicious_ips=frozenset({"203.0.113.42"}),
        keywords_by_category={
            "credential": ("login", "password", "account"),
            "urgency": ("verify now", "suspended"),
        },
    )


@pytest.fixture
def scanner(threat_intel: ThreatIntel) -> PhishingScanner:
    return PhishingScanner(threat_intel)
