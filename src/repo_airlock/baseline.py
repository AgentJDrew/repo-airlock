"""Baseline file support: acknowledge known false positives so they stop
appearing (and stop tripping --fail-on) on subsequent scans.

Format is a plain JSON file: a list of fingerprint strings, as produced by
``Finding.fingerprint()``. Kept intentionally simple (no timestamps/owners)
so it's easy to hand-edit and diff in code review.
"""

from __future__ import annotations

import json
from pathlib import Path

from repo_airlock.findings import Finding


def load_baseline(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if isinstance(data, dict):
        data = data.get("suppressed", [])
    if not isinstance(data, list):
        return set()
    return {str(item) for item in data}


def apply_baseline(findings: list[Finding], baseline: set[str]) -> tuple[list[Finding], int]:
    """Split findings into (kept, suppressed_count) using the baseline fingerprints."""
    if not baseline:
        return findings, 0
    kept = [f for f in findings if f.fingerprint() not in baseline]
    suppressed = len(findings) - len(kept)
    return kept, suppressed


def write_baseline(path: Path, findings: list[Finding]) -> None:
    """Write the current findings' fingerprints as a fresh baseline (overwrites)."""
    fingerprints = sorted({f.fingerprint() for f in findings})
    payload = {"suppressed": fingerprints}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
