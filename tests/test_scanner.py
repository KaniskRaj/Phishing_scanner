from __future__ import annotations

from phishing_scanner.models import Verdict
from phishing_scanner.scanner import PhishingScanner
from phishing_scanner.threat_intel import ThreatIntel


def test_known_malicious_domain_is_flagged_malicious(scanner: PhishingScanner) -> None:
    result = scanner.scan("https://totally-not-paypal.com/secure")
    assert result.verdict is Verdict.MALICIOUS
    assert any(s.name == "known_malicious_domain" for s in result.signals)


def test_known_malicious_ip_is_flagged_malicious(scanner: PhishingScanner) -> None:
    result = scanner.scan("http://203.0.113.42/wp-login.php")
    assert result.verdict is Verdict.MALICIOUS
    assert any(s.name == "known_malicious_ip" for s in result.signals)


def test_legitimate_url_with_login_in_path_is_not_malicious(scanner: PhishingScanner) -> None:
    # This is the core bug in the original implementation: a single keyword
    # match (e.g. "login") used to be enough to declare a URL malicious.
    result = scanner.scan("https://mybank.com/login")
    assert result.verdict is not Verdict.MALICIOUS


def test_clean_https_url_with_no_signals_is_safe(scanner: PhishingScanner) -> None:
    result = scanner.scan("https://www.wikipedia.org/wiki/Phishing")
    assert result.verdict is Verdict.SAFE
    assert result.score == 0


def test_raw_ip_host_contributes_but_does_not_alone_reach_malicious(
    scanner: PhishingScanner,
) -> None:
    result = scanner.scan("https://198.51.100.7/")
    assert result.verdict is not Verdict.MALICIOUS
    assert any(s.name == "raw_ip_host" for s in result.signals)


def test_missing_https_is_a_weak_signal_only(scanner: PhishingScanner) -> None:
    result = scanner.scan("http://example.com/")
    assert result.verdict is Verdict.SAFE
    assert any(s.name == "missing_https" for s in result.signals)


def test_excessive_subdomains_detected(scanner: PhishingScanner) -> None:
    result = scanner.scan("https://secure.login.account.example.com/")
    assert any(s.name == "excessive_subdomains" for s in result.signals)


def test_multiple_weak_signals_can_compound_to_suspicious(scanner: PhishingScanner) -> None:
    # http (weak) + a credential keyword (weak) + deep subdomain (weak) should
    # be able to add up to at least SUSPICIOUS even though none alone would.
    result = scanner.scan("http://account.login.verify.example.com/password")
    assert result.verdict is not Verdict.SAFE


def test_keyword_matches_are_capped(scanner: PhishingScanner) -> None:
    intel = ThreatIntel(
        malicious_domains=frozenset(),
        malicious_ips=frozenset(),
        keywords_by_category={"general": ("a", "b", "c", "d", "e", "f", "g", "h")},
    )
    scanner_local = PhishingScanner(intel)
    result = scanner_local.scan("https://example.com/a-b-c-d-e-f-g-h")
    keyword_signal = next(s for s in result.signals if s.name == "suspicious_keywords")
    assert keyword_signal.weight == scanner_local._weights.keyword_match_cap


def test_url_without_scheme_is_handled(scanner: PhishingScanner) -> None:
    result = scanner.scan("totally-not-paypal.com/secure")
    assert result.verdict is Verdict.MALICIOUS


def test_result_to_dict_round_trips_basic_fields(scanner: PhishingScanner) -> None:
    result = scanner.scan("https://example.com")
    payload = result.to_dict()
    assert payload["url"] == "https://example.com"
    assert payload["verdict"] == "safe"
    assert isinstance(payload["signals"], list)
