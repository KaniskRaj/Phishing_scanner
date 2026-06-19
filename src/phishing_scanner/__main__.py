"""Allows running the tool as ``python -m phishing_scanner``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
