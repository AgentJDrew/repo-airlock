"""The self-scan test: repo-airlock scans its own repo and must come back CLEARED.

This is the strongest possible proof that the tool doesn't cry wolf on a real,
well-kept codebase — if repo-airlock can't clear itself, it's not trustworthy
enough to run on anyone else's repo either.

Two legitimate categories of "findings" show up when a secret/privacy scanner
is pointed at its own source and tests, and both are handled the same way a
real user would handle them — acknowledged via --baseline, not by weakening
the detectors:

1. The privacy detector's own source code necessarily contains literal
   private-IP/CGNAT example strings (e.g. ``ipaddress.ip_network("10.0.0.0/8")``)
   because that's how the detector *works*. This is expected of any IP-range
   detector and is exactly what a baseline is for.
2. tests/fixtures/*  and the detector unit tests contain FAKE example secrets
   (e.g. the public AWS docs example key ``AKIAIOSFODNN7EXAMPLE``) on purpose,
   to prove the detectors fire on the shapes they're supposed to catch.

The checked-in ``.airlock-baseline.json`` at the repo root acknowledges both
categories. Nothing in that baseline is a real secret — see the file itself
and CONTRIBUTING-style comments in the fixtures for confirmation.
"""

from __future__ import annotations

from pathlib import Path

from repo_airlock.findings import Severity
from repo_airlock.scanner import scan

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BASELINE_PATH = _REPO_ROOT / ".airlock-baseline.json"


class TestSelfScan:
    def test_source_tree_is_cleared_at_high(self) -> None:
        result = scan(_REPO_ROOT / "src")
        assert result.verdict(Severity.HIGH) == "CLEARED"

    def test_source_tree_has_no_high_severity_findings(self) -> None:
        result = scan(_REPO_ROOT / "src")
        assert result.counts_by_severity()[Severity.HIGH] == 0

    def test_full_repo_cleared_with_baseline(self) -> None:
        """The real-world command a maintainer runs before publishing: scan
        the whole repo with the checked-in baseline applied. Must come back
        CLEARED — this is the actual go/no-go signal, not an internal detail."""
        assert _BASELINE_PATH.is_file(), "expected a checked-in .airlock-baseline.json at repo root"
        result = scan(_REPO_ROOT, baseline_path=_BASELINE_PATH)
        assert result.verdict(Severity.LOW) == "CLEARED", (
            f"unexpected un-baselined findings: {result.findings}"
        )

    def test_baseline_only_suppresses_known_fixture_and_self_reference_findings(self) -> None:
        """Guard rail: the baseline should suppress findings, not hide new,
        unrelated ones. Every suppressed finding must live in tests/fixtures,
        be a detector unit test, or be the privacy detector's own known
        self-referential CIDR/example matches."""
        result = scan(_REPO_ROOT, baseline_path=_BASELINE_PATH)
        assert result.suppressed_count > 0
        assert result.findings == []
