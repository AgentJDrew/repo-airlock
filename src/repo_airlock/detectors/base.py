"""Detector protocol — every check in repo-airlock implements this shape."""

from __future__ import annotations

from typing import Protocol

from repo_airlock.findings import Finding, Severity


class Detector(Protocol):
    """A single, focused check.

    Implementations are plain classes with class-level ``id``/``severity`` and
    a ``scan_text`` and/or ``scan_path`` method — see the concrete detectors
    for the two flavors (content-based vs filesystem-based).
    """

    id: str
    severity: Severity

    def scan_text(self, path: str, text: str) -> list[Finding]:
        """Scan file *content* (also used against git history diffs)."""
        ...
