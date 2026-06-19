"""Exceptions raised by the phishing_scanner package."""

from __future__ import annotations


class PhishingScannerError(Exception):
    """Base class for all errors raised by this package."""


class ThreatIntelUnavailableError(PhishingScannerError):
    """Raised when threat intel can't be loaded from network or cache."""
