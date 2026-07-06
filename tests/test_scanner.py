"""Integration tests for the full scanner over a small synthetic repo."""

from __future__ import annotations

from pathlib import Path

from repo_airlock.baseline import write_baseline
from repo_airlock.findings import Severity
from repo_airlock.scanner import scan


def _make_dirty_repo(tmp_path: Path) -> Path:
    (tmp_path / "README.md").write_text(
        "# Real project\n\nThis README has enough content in it to not be considered a stub file by the hygiene check."
    )
    (tmp_path / "LICENSE").write_text("MIT License " * 10)
    (tmp_path / ".gitignore").write_text("*.pyc\n")
    (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
    (tmp_path / ".env").write_text("SECRET=1\n")
    return tmp_path


def _make_clean_repo(tmp_path: Path) -> Path:
    (tmp_path / "README.md").write_text(
        "# Real project\n\nThis README has enough content in it to not be considered a stub file by the hygiene check."
    )
    (tmp_path / "LICENSE").write_text("MIT License " * 10)
    (tmp_path / ".gitignore").write_text("*.pyc\n")
    (tmp_path / "main.py").write_text("def add(a, b):\n    return a + b\n")
    return tmp_path


class TestScanner:
    def test_dirty_repo_produces_high_severity_findings(self, tmp_path: Path) -> None:
        root = _make_dirty_repo(tmp_path)
        result = scan(root)
        assert result.max_severity() == Severity.HIGH
        assert result.verdict(Severity.HIGH) == "HOLD"

    def test_clean_repo_is_cleared(self, tmp_path: Path) -> None:
        root = _make_clean_repo(tmp_path)
        result = scan(root)
        assert result.verdict(Severity.LOW) == "CLEARED"

    def test_files_scanned_count(self, tmp_path: Path) -> None:
        root = _make_clean_repo(tmp_path)
        result = scan(root)
        # README, LICENSE, .gitignore, main.py are all scannable text files
        assert result.files_scanned == 4

    def test_baseline_suppresses_known_finding(self, tmp_path: Path) -> None:
        root = _make_dirty_repo(tmp_path)
        first_result = scan(root)
        baseline_path = tmp_path.parent / "baseline.json"
        write_baseline(baseline_path, first_result.findings)

        second_result = scan(root, baseline_path=baseline_path)
        assert second_result.findings == []
        assert second_result.suppressed_count == len(first_result.findings)

    def test_findings_sorted_by_severity_desc(self, tmp_path: Path) -> None:
        root = _make_dirty_repo(tmp_path)
        result = scan(root)
        severities = [f.severity for f in result.findings]
        assert severities == sorted(severities, reverse=True)

    def test_history_not_scanned_by_default(self, tmp_path: Path) -> None:
        root = _make_clean_repo(tmp_path)
        result = scan(root)
        assert result.history_scanned is False

    def test_no_secret_value_leaks_into_findings(self, tmp_path: Path) -> None:
        root = _make_dirty_repo(tmp_path)
        result = scan(root)
        for f in result.findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in f.match_redacted
            assert "AKIAIOSFODNN7EXAMPLE" not in f.message
