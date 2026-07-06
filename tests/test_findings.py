"""Tests for Severity/Finding/ScanResult core logic."""

from __future__ import annotations

from repo_airlock.findings import Finding, ScanResult, Severity


class TestSeverity:
    def test_ordering(self) -> None:
        assert Severity.LOW < Severity.MEDIUM < Severity.HIGH

    def test_from_str(self) -> None:
        assert Severity.from_str("high") == Severity.HIGH
        assert Severity.from_str("MEDIUM") == Severity.MEDIUM

    def test_from_str_invalid_raises(self) -> None:
        try:
            Severity.from_str("critical")
            raised = False
        except ValueError:
            raised = True
        assert raised


class TestFinding:
    def test_redaction_never_stores_marker_of_full_value(self) -> None:
        f = Finding(
            detector_id="x", severity=Severity.LOW, message="m", path="p", line=1,
            match_redacted="AKIA...MPLE",
        )
        assert f.match_redacted == "AKIA...MPLE"

    def test_fingerprint_stable_for_identical_findings(self) -> None:
        f1 = Finding(detector_id="x", severity=Severity.LOW, message="m", path="p", line=1, match_redacted="a...b")
        f2 = Finding(detector_id="x", severity=Severity.LOW, message="m2", path="p", line=1, match_redacted="a...b")
        assert f1.fingerprint() == f2.fingerprint()  # message not part of identity

    def test_fingerprint_differs_by_path(self) -> None:
        f1 = Finding(detector_id="x", severity=Severity.LOW, message="m", path="p1", line=1, match_redacted="a...b")
        f2 = Finding(detector_id="x", severity=Severity.LOW, message="m", path="p2", line=1, match_redacted="a...b")
        assert f1.fingerprint() != f2.fingerprint()

    def test_location_marks_history_findings(self) -> None:
        f = Finding(
            detector_id="x", severity=Severity.LOW, message="m", path="p", line=0,
            in_history=True, commit="abcdef1234567890",
        )
        assert "history" in f.location()
        assert "abcdef12" in f.location()


class TestScanResult:
    def test_verdict_cleared_when_no_findings(self) -> None:
        result = ScanResult()
        assert result.verdict(Severity.HIGH) == "CLEARED"
        assert result.exit_code(Severity.HIGH) == 0

    def test_verdict_hold_when_findings_at_or_above_threshold(self) -> None:
        result = ScanResult(findings=[
            Finding(detector_id="x", severity=Severity.HIGH, message="m", path="p", line=1),
        ])
        assert result.verdict(Severity.HIGH) == "HOLD"
        assert result.exit_code(Severity.HIGH) == 1

    def test_verdict_cleared_when_findings_below_threshold(self) -> None:
        result = ScanResult(findings=[
            Finding(detector_id="x", severity=Severity.LOW, message="m", path="p", line=1),
        ])
        assert result.verdict(Severity.HIGH) == "CLEARED"
        assert result.exit_code(Severity.HIGH) == 0

    def test_counts_by_severity(self) -> None:
        result = ScanResult(findings=[
            Finding(detector_id="a", severity=Severity.HIGH, message="m", path="p", line=1),
            Finding(detector_id="b", severity=Severity.HIGH, message="m", path="p", line=2),
            Finding(detector_id="c", severity=Severity.LOW, message="m", path="p", line=3),
        ])
        counts = result.counts_by_severity()
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.LOW] == 1
        assert counts[Severity.MEDIUM] == 0
