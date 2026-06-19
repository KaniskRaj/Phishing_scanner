"""phishing-scanner: heuristic phishing URL scanner with risk scoring."""

from .models import ScanResult, Signal, Verdict
from .scanner import PhishingScanner, ScoringWeights, Thresholds
from .threat_intel import ThreatIntel, ThreatIntelRepository

__version__ = "1.0.0"

__all__ = [
    "PhishingScanner",
    "ScanResult",
    "ScoringWeights",
    "Signal",
    "ThreatIntel",
    "ThreatIntelRepository",
    "Thresholds",
    "Verdict",
]
