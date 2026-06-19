# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — Unreleased

### Changed (breaking, relative to the original script)

- Rebuilt as an installable package (`src/phishing_scanner/`) instead of a
  single top-level script. Entry point is now the `phishing-scanner` console
  command (or `python -m phishing_scanner`), not `python Phishing_scanner.py`.
- Replaced the boolean OR-of-heuristics detector with a weighted risk-scoring
  engine and a three-tier verdict (`safe` / `suspicious` / `malicious`)
  instead of a binary malicious/safe flag.
- Moved threat-intel feeds from `Phishing.Database-master/Lists/` to a
  flattened top-level `data/` directory.
- `data/keywords.txt` is now categorized (`category: term, term`) instead of
  one flat list, and supports `#` comments.

### Added

- Local on-disk caching of threat-intel feeds with a configurable TTL,
  retrying HTTP session, and graceful fallback to stale cache on network
  failure (previously: no timeout, no retry, no cache, hard crash on
  failure).
- `--offline` mode that uses cached data only.
- The previously-unused malicious-IP list is now actually checked.
- Domain/IP lookups now use `frozenset` instead of `list` (O(1) vs O(n) per
  scan against a 461k-entry list).
- CLI subcommands: `scan` (single/batch/file/JSON), `interactive` (original
  prompt-loop UX, preserved), `update`.
- Defined exit codes (`0`/`1`/`2`) for scripting and CI use.
- Full type hints, docstrings, structured logging (`logging` instead of
  bare `print`).
- Test suite (pytest, 90%+ coverage), linting/formatting (ruff), type
  checking (mypy), pre-commit config, and GitHub Actions CI across Python
  3.9–3.12.
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, this changelog.

### Fixed

- Keyword matching previously flagged any URL containing common words like
  `login`, `account`, `free`, or `bank` as outright malicious, regardless of
  domain reputation. This produced a very high false-positive rate (e.g.
  `https://mybank.com/login`). It's now one weak, capped signal among
  several.
- The default raw-GitHub feed URLs pointed at `Phishing-Scanner` (note the
  casing) on a `main` branch path that didn't resolve against the actual
  repository, so the original script's documented defaults were broken at
  the URL level even before considering content.
