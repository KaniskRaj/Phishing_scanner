"""Loading and caching of threat-intel feeds (malicious domains, IPs, keywords).

The original implementation re-downloaded a ~13MB domain list from GitHub on
every single run, with no timeout and no fallback if the request failed.
This module fixes that: feeds are fetched through a retrying ``requests``
session, written to a local on-disk cache with a TTL, and -- if the network
is unavailable -- served from the last good cache instead of crashing.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .exceptions import ThreatIntelUnavailableError

logger = logging.getLogger(__name__)

DEFAULT_DOMAINS_URL = (
    "https://raw.githubusercontent.com/KaniskRaj/Phishing_scanner/main/data/domains.txt"
)
DEFAULT_IPS_URL = "https://raw.githubusercontent.com/KaniskRaj/Phishing_scanner/main/data/ips.txt"
DEFAULT_KEYWORDS_URL = (
    "https://raw.githubusercontent.com/KaniskRaj/Phishing_scanner/main/data/keywords.txt"
)

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h: this feed updates daily upstream, not per-second


def default_cache_dir() -> Path:
    """Return an OS-appropriate cache directory without adding a dependency."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
    else:
        base = os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))
    return Path(base) / "phishing-scanner"


def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session


@dataclass(frozen=True)
class ThreatIntel:
    """In-memory threat intel, ready for O(1) lookups."""

    malicious_domains: frozenset[str]
    malicious_ips: frozenset[str]
    keywords_by_category: dict[str, tuple[str, ...]]

    @property
    def all_keywords(self) -> Iterable[str]:
        for kws in self.keywords_by_category.values():
            yield from kws


class ThreatIntelRepository:
    """Fetches threat-intel feeds, with on-disk caching and graceful fallback.

    Parameters
    ----------
    domains_url, ips_url, keywords_url:
        Sources for the three feeds. Defaults point at the public
        Phishing.Database-derived lists bundled with this project's origin
        repo, but any compatible feed URL (or a local ``file://`` path) works.
    cache_dir:
        Where downloaded feeds are cached. Defaults to an OS cache dir.
    cache_ttl_seconds:
        How long a cached copy is considered fresh before a re-fetch is
        attempted. Stale cache is still used as a fallback if the network
        is unavailable.
    timeout_seconds:
        Per-request network timeout. The original script had none, which
        meant a slow/dead endpoint could hang the tool forever.
    """

    def __init__(
        self,
        domains_url: str = DEFAULT_DOMAINS_URL,
        ips_url: str = DEFAULT_IPS_URL,
        keywords_url: str = DEFAULT_KEYWORDS_URL,
        cache_dir: Path | None = None,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        self._urls = {
            "domains": domains_url,
            "ips": ips_url,
            "keywords": keywords_url,
        }
        self._cache_dir = cache_dir or default_cache_dir()
        self._cache_ttl = cache_ttl_seconds
        self._timeout = timeout_seconds
        self._session = session or _build_session()

    def load(self, *, force_refresh: bool = False, offline: bool = False) -> ThreatIntel:
        """Load all three feeds, returning ready-to-query ``ThreatIntel``."""
        domains_text = self._get_feed("domains", force_refresh=force_refresh, offline=offline)
        ips_text = self._get_feed("ips", force_refresh=force_refresh, offline=offline)
        keywords_text = self._get_feed("keywords", force_refresh=force_refresh, offline=offline)

        return ThreatIntel(
            malicious_domains=frozenset(_split_lines(domains_text)),
            malicious_ips=frozenset(_split_lines(ips_text)),
            keywords_by_category=_parse_keywords(keywords_text),
        )

    def _get_feed(self, name: str, *, force_refresh: bool, offline: bool) -> str:
        cache_path = self._cache_dir / f"{name}.txt"

        if offline:
            cached = self._read_cache(cache_path)
            if cached is None:
                raise ThreatIntelUnavailableError(
                    f"Offline mode requested but no cached '{name}' feed is available at "
                    f"{cache_path}. Run once with network access first."
                )
            return cached

        if not force_refresh and self._is_fresh(cache_path):
            cached = self._read_cache(cache_path)
            if cached is not None:
                return cached

        try:
            text = self._download(self._urls[name])
        except requests.RequestException as exc:
            logger.warning("Failed to download '%s' feed (%s); falling back to cache.", name, exc)
            cached = self._read_cache(cache_path)
            if cached is not None:
                return cached
            raise ThreatIntelUnavailableError(
                f"Could not download '{name}' feed and no cache is available."
            ) from exc

        self._write_cache(cache_path, text)
        return text

    def _download(self, url: str) -> str:
        response = self._session.get(url, timeout=self._timeout)
        response.raise_for_status()
        return response.text

    def _is_fresh(self, path: Path) -> bool:
        if not path.exists():
            return False
        age = time.time() - path.stat().st_mtime
        return age < self._cache_ttl

    @staticmethod
    def _read_cache(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return None

    @staticmethod
    def _write_cache(path: Path, text: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            # Caching is an optimization, not a correctness requirement --
            # a failure here (e.g. read-only filesystem) shouldn't crash a scan.
            logger.debug("Could not write cache file %s: %s", path, exc)


def _split_lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield line.lower()


def _parse_keywords(text: str) -> dict[str, tuple[str, ...]]:
    """Parse the keyword feed.

    Supports the upstream "category: term, term" format. Plain one-term-per-
    line files (no colon) are accepted too, bucketed under "general", so the
    bundled default feed (which has no categories) still works. Lines
    starting with "#" are treated as comments and skipped.
    """
    categorized: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            category, keywords_str = line.split(":", 1)
            terms = [kw.strip().lower() for kw in keywords_str.split(",") if kw.strip()]
        else:
            category, terms = "general", [line.lower()]
        if not terms:
            continue
        categorized.setdefault(category.strip().lower(), []).extend(terms)
    return {category: tuple(terms) for category, terms in categorized.items()}
