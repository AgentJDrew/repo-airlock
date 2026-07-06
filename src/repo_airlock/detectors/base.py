"""Detector protocol — every check in repo-airlock implements this shape."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from repo_airlock.findings import Finding, Severity

# Defense-in-depth cap on how much of a single line the content detectors will
# hand to their regexes. repo-airlock reads ARBITRARY, untrusted file content
# (and git-history diffs), so a single pathologically long line — a minified JS
# bundle, a giant base64 blob, or a crafted file in a malicious repo — must not
# be able to pump unbounded work into the (now-linear) regexes. Every legitimate
# secret/email/IP/path finding lives well within this window and near the start
# of its line; content past the cap is third-party/minified noise that a human
# never audits line-by-line anyway. This bound, combined with the ~2MB
# whole-file cap in walker.py, keeps worst-case scan time linear and small.
MAX_SCAN_LINE_LEN = 64 * 1024  # 64 KB per line


def iter_scannable_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(lineno, line)`` pairs, truncating any single line to
    :data:`MAX_SCAN_LINE_LEN` characters before it reaches a detector regex.

    Line numbers are preserved (truncation only shortens the content handed to
    the regex engine, it never drops or renumbers lines), so reported locations
    stay accurate.
    """
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_SCAN_LINE_LEN:
            line = line[:MAX_SCAN_LINE_LEN]
        yield lineno, line


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
