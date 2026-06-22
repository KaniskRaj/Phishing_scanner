# Contributing

Thanks for considering a contribution.

## Setup

```bash
git clone https://github.com/KaniskRaj/Phishing_scanner.git
cd Phishing_scanner
pip install -e ".[dev]"
pre-commit install   # optional, but recommended
```

## Before opening a PR

```bash
ruff check src tests
ruff format src tests
mypy src
pytest
```

All four must pass; CI re-runs them on every PR across Python 3.9–3.12.

## Guidelines

- **New heuristics**: add a weighted `Signal` in `scanner.py` rather than a
  boolean short-circuit. A single weak signal should not be able to flip the
  verdict straight to `malicious` on its own — that's the false-positive
  trap the original version of this tool had. If you believe a signal
  *should* be decisive on its own, give it a weight at or above the
  `malicious` threshold and say so in the docstring/PR description.
- **New threat-intel feeds**: keep the `category: term, term` format in
  `data/keywords.txt` so existing parsing keeps working, or extend
  `threat_intel.py`'s parser and add tests for the new format.
- **Tests**: every new heuristic or CLI flag needs a test. PRs that change
  scoring behavior should include a test asserting the specific behavior
  changed (e.g. "this URL now reaches `suspicious` but not `malicious`").
- Keep runtime dependencies minimal. This is a security tool; new
  dependencies are new supply-chain surface and need a good reason.
