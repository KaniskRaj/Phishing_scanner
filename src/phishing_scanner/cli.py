"""Command-line interface for phishing-scanner.

Examples
--------
    phishing-scanner scan https://example.com
    phishing-scanner scan -f urls.txt --json
    phishing-scanner interactive
    phishing-scanner update --force
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from .exceptions import PhishingScannerError
from .models import ScanResult, Verdict
from .scanner import PhishingScanner
from .threat_intel import ThreatIntelRepository

logger = logging.getLogger("phishing_scanner")

EXIT_SAFE = 0
EXIT_THREAT_FOUND = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-scanner",
        description="Heuristic phishing URL scanner with risk scoring.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use cached threat intel only; never hit the network",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="force a fresh download of threat intel feeds",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan one or more URLs")
    scan_parser.add_argument("urls", nargs="*", help="URL(s) to scan")
    scan_parser.add_argument("-f", "--file", type=Path, help="path to a file with one URL per line")
    scan_parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON instead of text"
    )

    subparsers.add_parser(
        "interactive", help="prompt for URLs one at a time (original tool's behavior)"
    )

    update_parser = subparsers.add_parser("update", help="refresh the cached threat intel")
    update_parser.add_argument(
        "--force", action="store_true", help="bypass the cache TTL and refetch regardless"
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        repo = ThreatIntelRepository()
        intel = repo.load(force_refresh=args.no_cache, offline=args.offline)
        scanner = PhishingScanner(intel)

        if args.command == "scan":
            return _run_scan(scanner, args)
        if args.command == "interactive":
            return _run_interactive(scanner)
        if args.command == "update":
            repo.load(force_refresh=True, offline=False)
            print("Threat intel cache refreshed.")
            return EXIT_SAFE

    except PhishingScannerError as exc:
        logger.error(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_ERROR


def _collect_urls(args: argparse.Namespace) -> list[str]:
    urls: list[str] = list(args.urls)
    if args.file:
        text = args.file.read_text(encoding="utf-8")
        urls.extend(line.strip() for line in text.splitlines() if line.strip())
    if not urls:
        raise PhishingScannerError("No URLs provided. Pass URL(s), or use -f/--file.")
    return urls


def _run_scan(scanner: PhishingScanner, args: argparse.Namespace) -> int:
    urls = _collect_urls(args)
    results = [scanner.scan(url) for url in urls]

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for result in results:
            _print_result(result)

    return EXIT_THREAT_FOUND if any(r.verdict is not Verdict.SAFE for r in results) else EXIT_SAFE


def _run_interactive(scanner: PhishingScanner) -> int:
    print("Enter URLs to scan, type 'done' when finished:")
    results: list[ScanResult] = []
    while True:
        try:
            url = input("URL: ").strip()
        except EOFError:
            break
        if url.lower() == "done":
            break
        if not url:
            continue
        results.append(scanner.scan(url))

    print()
    for verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.SAFE):
        matching = [r for r in results if r.verdict is verdict]
        if not matching:
            continue
        print(f"{verdict.value.upper()}:")
        for result in matching:
            _print_result(result, indent="  ")

    return EXIT_THREAT_FOUND if any(r.verdict is not Verdict.SAFE for r in results) else EXIT_SAFE


def _print_result(result: ScanResult, indent: str = "") -> None:
    print(f"{indent}[{result.verdict.value.upper()}] (score {result.score}) {result.url}")
    for signal in result.signals:
        print(f"{indent}    - {signal.detail} (+{signal.weight})")


if __name__ == "__main__":
    sys.exit(main())
