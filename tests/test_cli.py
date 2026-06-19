from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from phishing_scanner import cli
from phishing_scanner.threat_intel import ThreatIntel


@pytest.fixture(autouse=True)
def _patch_threat_intel() -> None:
    """Every CLI test runs fully offline against a small, fixed intel set."""
    intel = ThreatIntel(
        malicious_domains=frozenset({"totally-not-paypal.com"}),
        malicious_ips=frozenset(),
        keywords_by_category={"credential": ("login",)},
    )
    with patch("phishing_scanner.cli.ThreatIntelRepository") as repo_cls:
        repo_cls.return_value.load.return_value = intel
        yield


def test_scan_safe_url_returns_exit_zero(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["scan", "https://example.com"])
    assert exit_code == cli.EXIT_SAFE
    out = capsys.readouterr().out
    assert "SAFE" in out


def test_scan_malicious_url_returns_exit_one() -> None:
    exit_code = cli.main(["scan", "https://totally-not-paypal.com"])
    assert exit_code == cli.EXIT_THREAT_FOUND


def test_scan_json_output_is_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["scan", "--json", "https://totally-not-paypal.com"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload[0]["verdict"] == "malicious"


def test_scan_from_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("https://example.com\nhttps://totally-not-paypal.com\n")

    exit_code = cli.main(["scan", "-f", str(urls_file)])
    out = capsys.readouterr().out
    assert exit_code == cli.EXIT_THREAT_FOUND
    assert "example.com" in out
    assert "totally-not-paypal.com" in out


def test_scan_with_no_urls_and_no_file_errors_cleanly() -> None:
    exit_code = cli.main(["scan"])
    assert exit_code == cli.EXIT_ERROR


def test_interactive_mode_reads_until_done(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = iter(["https://example.com", "done"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))

    exit_code = cli.main(["interactive"])
    out = capsys.readouterr().out
    assert exit_code == cli.EXIT_SAFE
    assert "example.com" in out
