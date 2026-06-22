# phishing-scanner

[![CI](https://github.com/KaniskRaj/Phishing_scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/KaniskRaj/Phishing_scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

A small, dependency-light CLI and Python library for heuristically scoring
whether a URL looks like phishing, using a combination of:

- a known-malicious **domain** blocklist
- a known-malicious **IP** blocklist
- structural red flags (raw IP host, missing HTTPS, abnormally deep
  subdomains)
- suspicious **keyword** matches (login/credential/financial terms)

Each signal contributes a weight to a 0–100+ risk score, which maps onto a
`safe` / `suspicious` / `malicious` verdict. **This is not proof of
phishing** — it's a fast, offline-friendly triage signal meant to flag URLs
for closer review or for blocking in a pipeline, not a substitute for a full
URL-reputation service.

## Why a rewrite

This started as a single ~85-line script that downloaded a domain list and
ran a handful of `if` checks. It worked, but had problems that go beyond
style:

| Problem | Before | After |
|---|---|---|
| False positives | Any keyword match (e.g. `login`, `free`, `account`) anywhere in the URL → instant `malicious` verdict | Weighted scoring; weak signals only add up to `suspicious`, near-certain signals (blocklist hits) reach `malicious` |
| Lookup performance | `website in malicious_domains` against a 461k-item **list** (O(n) per scan) | Loaded into a `frozenset` (O(1) lookup) |
| Unused data | A 7,898-entry malicious-IP list shipped but never checked | Actually used as a scoring signal |
| Network resilience | No timeout, no retry, no caching — re-downloaded ~13MB on every run, crashed on any network hiccup | Retrying session with timeout, on-disk TTL cache, graceful fallback to stale cache, explicit `--offline` mode |
| Testability | Network calls fired at *import time*; impossible to unit test without hitting the network | Lazy loading via a repository class; fully mockable |
| Usability | Blocking `input()` loop only | `scan <url>`, `scan -f file.txt`, `--json`, `interactive`, `update`, with real exit codes for CI/automation |
| Quality gates | None | pytest (90%+ coverage), ruff (lint + format), mypy (strict-ish), GitHub Actions CI across Python 3.9–3.12 |

## Installation

```bash
pip install -e .
# or, for development:
pip install -e ".[dev]"
```

Requires Python 3.9+. Runtime dependencies are intentionally minimal
(`requests`, `tldextract`) — this is a security tool, and every added
dependency is additional supply-chain surface.

## Usage

```bash
# Scan one or more URLs
phishing-scanner scan https://example.com https://192.0.2.10/wp-login.php

# Scan a file of URLs (one per line)
phishing-scanner scan -f urls.txt

# Machine-readable output, for piping into other tools
phishing-scanner scan --json https://example.com

# Original interactive prompt-loop behavior
phishing-scanner interactive

# Force-refresh the cached threat-intel feeds
phishing-scanner update --force

# Use only the local cache, no network access at all
phishing-scanner --offline scan https://example.com
```

Exit codes (useful in CI / pre-commit hooks / mail pipelines):

| Code | Meaning |
|---|---|
| `0` | All scanned URLs were `safe` |
| `1` | At least one URL was `suspicious` or `malicious` |
| `2` | A runtime error occurred (e.g. no threat intel available) |

### As a library

```python
from phishing_scanner import PhishingScanner, ThreatIntelRepository

intel = ThreatIntelRepository().load()
scanner = PhishingScanner(intel)

result = scanner.scan("https://totally-not-paypal.com/secure-login")
print(result.verdict, result.score)
for signal in result.signals:
    print(f"  {signal.name}: {signal.detail} (+{signal.weight})")
```

## How scoring works

See [`scanner.py`](src/phishing_scanner/scanner.py) for the authoritative
logic. Defaults:

| Signal | Weight | Notes |
|---|---|---|
| Domain on known-malicious list | 100 | Reaches `malicious` alone |
| IP on known-malicious list | 100 | Reaches `malicious` alone |
| Raw IP used as host | 35 | e.g. `http://198.51.100.7/login` |
| Excessive subdomain depth | 25 | e.g. `secure.login.verify.example.com` |
| Missing HTTPS | 12 | Weak alone |
| Suspicious keyword match(es) | 8 each, capped at 24 | Weak alone, capped so keyword-stuffing can't dominate the score |

Verdict thresholds: `score ≥ 70` → `malicious`, `30 ≤ score < 70` →
`suspicious`, else `safe`. Both weights and thresholds are configurable via
`ScoringWeights` / `Thresholds` if you want to tune sensitivity for your own
data.

## Threat intel data

The feeds live in [`data/`](data/) and are fetched + cached locally (default
TTL: 24h) rather than re-downloaded on every run:

- `data/domains.txt` — known phishing domains
- `data/ips.txt` — known phishing-hosting IPs
- `data/keywords.txt` — categorized suspicious terms (`category: term, term`)

If you maintain your own feed, point `ThreatIntelRepository` at your own
URLs (or a `file://` path) — the format is unchanged.

## Development

```bash
pip install -e ".[dev]"
pytest                       # run tests with coverage
ruff check src tests         # lint
ruff format src tests        # format
mypy src                     # type-check
pre-commit install           # optional: run the above automatically on commit
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push/PR
across Python 3.9–3.12.

## Limitations

- Heuristic, not authoritative — false positives and false negatives are
  both possible. Don't auto-block solely on this tool's output without a
  human or a secondary check in the loop for anything consequential.
  See [`SECURITY.md`](SECURITY.md) for related considerations.
- Blocklists go stale; a domain only just weaponized for phishing won't be
  on the list yet.

## License

MIT — see [`LICENSE`](LICENSE).
