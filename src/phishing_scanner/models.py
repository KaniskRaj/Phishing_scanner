"""Typed data structures shared across the scanner package."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """Overall risk classification for a scanned URL.

    A three-tier verdict (rather than a single malicious/safe boolean) is
    used deliberately: phishing heuristics are probabilistic signals, not
    proof. Collapsing them into a binary flag is what causes naive scanners
    to misclassify ordinary URLs (e.g. any link containing "login") as
    malicious. SUSPICIOUS gives callers a middle tier to route to manual
    review instead of an auto-block.
    """

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass(frozen=True)
class Signal:
    """A single heuristic finding produced while scanning a URL."""

    name: str
    weight: int
    detail: str


@dataclass(frozen=True)
class ScanResult:
    """The outcome of scanning a single URL."""

    url: str
    score: int
    verdict: Verdict
    signals: tuple[Signal, ...] = field(default_factory=tuple)

    @property
    def is_malicious(self) -> bool:
        return self.verdict is Verdict.MALICIOUS

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "score": self.score,
            "verdict": self.verdict.value,
            "signals": [
                {"name": s.name, "weight": s.weight, "detail": s.detail} for s in self.signals
            ],
        }
