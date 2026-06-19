# Security Policy

## Reporting a vulnerability

If you find a security issue in this project (e.g. a way to make the scanner
itself unsafe to run, not a gap in phishing detection coverage), please open
a private report via GitHub's "Report a vulnerability" feature on this
repository's Security tab, rather than a public issue. We'll do our best to
respond promptly.

## Scope and intended use

This tool produces a **heuristic risk score**, not a definitive verdict. It
is intended to assist triage (e.g. flagging URLs for review, or as one signal
among several in an automated pipeline), not to be the sole gate for
blocking access, sending abuse reports, or making decisions with legal or
financial consequences.

In particular:

- **False positives will happen.** A `suspicious` or even `malicious`
  verdict does not prove a URL is malicious.
- **False negatives will happen.** Newly registered phishing infrastructure
  will not yet be on any blocklist.
- Do not treat this tool's output as a substitute for a maintained,
  professionally curated URL-reputation service in any setting where being
  wrong has real consequences.

## Data handling

- Scanned URLs are processed locally; this tool does not transmit the URLs
  you scan to any third party.
- The only outbound network calls are to fetch the public threat-intel feeds
  configured in `threat_intel.py` (or your own, if configured) — not to
  report on what you scanned.
