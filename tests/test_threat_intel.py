from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

from phishing_scanner.exceptions import ThreatIntelUnavailableError
from phishing_scanner.threat_intel import ThreatIntelRepository

DOMAINS_URL = "https://example.test/domains.txt"
IPS_URL = "https://example.test/ips.txt"
KEYWORDS_URL = "https://example.test/keywords.txt"

DOMAINS_TEXT = "evil.example\nBAD.example\n"
IPS_TEXT = "203.0.113.42\n"
KEYWORDS_TEXT = "credential: login, password\nurgency: verify now\n"

FEED_TEXT_BY_URL = {
    DOMAINS_URL: DOMAINS_TEXT,
    IPS_URL: IPS_TEXT,
    KEYWORDS_URL: KEYWORDS_TEXT,
}


def _make_repo(tmp_path: Path, session: MagicMock) -> ThreatIntelRepository:
    return ThreatIntelRepository(
        domains_url=DOMAINS_URL,
        ips_url=IPS_URL,
        keywords_url=KEYWORDS_URL,
        cache_dir=tmp_path,
        session=session,
        timeout_seconds=1,
    )


def _mock_session(text_by_url: dict[str, str]) -> MagicMock:
    session = MagicMock()

    def fake_get(url: str, timeout: float) -> MagicMock:
        response = MagicMock()
        response.text = text_by_url.get(url, "")
        response.raise_for_status = MagicMock()
        return response

    session.get.side_effect = fake_get
    return session


def test_domains_are_lowercased_and_deduplicated_via_set(tmp_path: Path) -> None:
    session = _mock_session(FEED_TEXT_BY_URL)
    repo = _make_repo(tmp_path, session)
    intel = repo.load()

    assert "evil.example" in intel.malicious_domains
    assert "bad.example" in intel.malicious_domains  # lowercased
    assert "203.0.113.42" in intel.malicious_ips
    assert "login" in intel.keywords_by_category["credential"]
    assert "verify now" in intel.keywords_by_category["urgency"]


def test_successful_fetch_writes_cache_file(tmp_path: Path) -> None:
    session = _mock_session(FEED_TEXT_BY_URL)
    repo = _make_repo(tmp_path, session)
    repo.load()

    assert (tmp_path / "domains.txt").read_text() == DOMAINS_TEXT
    assert (tmp_path / "ips.txt").read_text() == IPS_TEXT
    assert (tmp_path / "keywords.txt").read_text() == KEYWORDS_TEXT


def test_fresh_cache_is_used_without_hitting_network(tmp_path: Path) -> None:
    (tmp_path / "domains.txt").write_text(DOMAINS_TEXT)
    (tmp_path / "ips.txt").write_text(IPS_TEXT)
    (tmp_path / "keywords.txt").write_text(KEYWORDS_TEXT)

    session = MagicMock()
    repo = _make_repo(tmp_path, session)
    intel = repo.load()

    session.get.assert_not_called()
    assert "evil.example" in intel.malicious_domains


def test_network_failure_falls_back_to_stale_cache(tmp_path: Path) -> None:
    (tmp_path / "domains.txt").write_text(DOMAINS_TEXT)
    (tmp_path / "ips.txt").write_text(IPS_TEXT)
    (tmp_path / "keywords.txt").write_text(KEYWORDS_TEXT)

    session = MagicMock()
    session.get.side_effect = requests.ConnectionError("network is down")
    repo = _make_repo(tmp_path, session)

    # force_refresh=True means it *tries* the network first, then falls back
    intel = repo.load(force_refresh=True)
    assert "evil.example" in intel.malicious_domains


def test_no_network_and_no_cache_raises_clear_error(tmp_path: Path) -> None:
    session = MagicMock()
    session.get.side_effect = requests.ConnectionError("network is down")
    repo = _make_repo(tmp_path, session)

    with pytest.raises(ThreatIntelUnavailableError):
        repo.load()


def test_offline_mode_without_cache_raises_clear_error(tmp_path: Path) -> None:
    session = MagicMock()
    repo = _make_repo(tmp_path, session)

    with pytest.raises(ThreatIntelUnavailableError):
        repo.load(offline=True)
    session.get.assert_not_called()
