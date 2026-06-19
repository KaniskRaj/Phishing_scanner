"""Heuristic risk-scoring engine for URLs.

Design note
-----------
The original scanner OR'd together independent boolean checks: if *any one*
heuristic fired (e.g. the URL contained the word "login", or wasn't HTTPS),
the URL was declared outright malicious. That makes the false-positive rate
unworkable in practice -- ``https://mybank.com/login`` trips the same alarm
as an actual credential-harvesting page.

This module instead assigns each heuristic a weight and sums them into a
0-100+ risk score, then maps that score onto a three-tier verdict. Strong,
near-definitive signals (a domain or IP that's on a known-malicious list)
carry enough weight to reach MALICIOUS on their own. Weak signals (a single
suspicious keyword, missing HTTPS) only nudge the score up and need to
co-occur with other weak signals to cross the SUSPICIOUS threshold.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

from .models import ScanResult, Signal, Verdict
from .threat_intel import ThreatIntel

_IP_HOST_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# tldextract defaults to fetching a live public-suffix list over the network
# and only falls back to its bundled snapshot on failure. For a security
# tool that should run deterministically (and offline, if requested), pin it
# to the bundled snapshot explicitly rather than depending on that fallback.
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())


@dataclass(frozen=True)
class ScoringWeights:
    """Tunable weights for each heuristic. Defaults are deliberately modest
    for weak signals and decisive for near-certain ones."""

    domain_on_blocklist: int = 100
    ip_on_blocklist: int = 100
    raw_ip_host: int = 35
    excessive_subdomains: int = 25
    missing_https: int = 12
    keyword_match: int = 8
    keyword_match_cap: int = 24  # multiple keyword hits stop adding value past this


@dataclass(frozen=True)
class Thresholds:
    """Score cutoffs that map onto a :class:`~phishing_scanner.models.Verdict`."""

    malicious: int = 70
    suspicious: int = 30


class PhishingScanner:
    """Scans URLs against loaded threat intel and returns a scored verdict."""

    def __init__(
        self,
        threat_intel: ThreatIntel,
        weights: ScoringWeights | None = None,
        thresholds: Thresholds | None = None,
    ) -> None:
        self._intel = threat_intel
        self._weights = weights or ScoringWeights()
        self._thresholds = thresholds or Thresholds()

    def scan(self, url: str) -> ScanResult:
        """Score a single URL and return a :class:`ScanResult`."""
        url = url.strip()
        signals: list[Signal] = []
        w = self._weights

        parsed = urlsplit(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        ext = _tld_extractor(url)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ""

        # --- Near-definitive signals -------------------------------------------------
        if registered_domain and registered_domain in self._intel.malicious_domains:
            signals.append(
                Signal(
                    "known_malicious_domain",
                    w.domain_on_blocklist,
                    f"'{registered_domain}' is on the malicious domain list",
                )
            )

        if host and _IP_HOST_RE.match(host) and host in self._intel.malicious_ips:
            signals.append(
                Signal(
                    "known_malicious_ip",
                    w.ip_on_blocklist,
                    f"'{host}' is on the malicious IP list",
                )
            )

        # --- Weaker, corroborating signals --------------------------------------------
        if host and _is_ip_literal(host):
            signals.append(
                Signal(
                    "raw_ip_host",
                    w.raw_ip_host,
                    "URL uses a raw IP address instead of a domain name",
                )
            )

        if ext.subdomain and ext.subdomain.count(".") >= 1:
            signals.append(
                Signal(
                    "excessive_subdomains",
                    w.excessive_subdomains,
                    f"unusually deep subdomain chain: '{ext.subdomain}'",
                )
            )

        if parsed.scheme.lower() != "https":
            signals.append(Signal("missing_https", w.missing_https, "connection is not HTTPS"))

        matched_keywords = sorted(_matched_keywords(url, self._intel.all_keywords))
        if matched_keywords:
            raw_score = len(matched_keywords) * w.keyword_match
            capped = min(raw_score, w.keyword_match_cap)
            signals.append(
                Signal(
                    "suspicious_keywords",
                    capped,
                    f"contains suspicious term(s): {', '.join(matched_keywords)}",
                )
            )

        total = sum(s.weight for s in signals)
        verdict = self._verdict_for(total)
        return ScanResult(url=url, score=total, verdict=verdict, signals=tuple(signals))

    def _verdict_for(self, score: int) -> Verdict:
        if score >= self._thresholds.malicious:
            return Verdict.MALICIOUS
        if score >= self._thresholds.suspicious:
            return Verdict.SUSPICIOUS
        return Verdict.SAFE


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _matched_keywords(url: str, keywords: Iterable[str]) -> set[str]:
    lowered = url.lower()
    found = set()
    for word in keywords:
        if re.search(re.escape(word), lowered):
            found.add(word)
    return found
