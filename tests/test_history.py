"""Tests for git history scanning — secrets removed later still leak."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from repo_airlock.history import scan_history


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


def _init_repo(root: Path) -> None:
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test User")


@pytest.fixture
def git_repo_with_removed_secret(tmp_path: Path) -> Path:
    _init_repo(tmp_path)

    secret_file = tmp_path / "config.py"
    secret_file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "add config with secret")

    secret_file.write_text('aws_key = "REDACTED"\n')
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "remove secret")

    return tmp_path


class TestHistoryScan:
    def test_finds_secret_that_was_later_removed(self, git_repo_with_removed_secret: Path) -> None:
        findings = scan_history(git_repo_with_removed_secret)
        assert any("AKIA" in f.match_redacted for f in findings)

    def test_findings_are_marked_in_history(self, git_repo_with_removed_secret: Path) -> None:
        findings = scan_history(git_repo_with_removed_secret)
        assert all(f.in_history for f in findings)

    def test_findings_carry_commit_hash(self, git_repo_with_removed_secret: Path) -> None:
        findings = scan_history(git_repo_with_removed_secret)
        assert all(len(f.commit) == 40 for f in findings)

    def test_non_git_directory_returns_no_findings(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_history(tmp_path)
        assert findings == []

    def test_clean_history_has_no_findings(self, tmp_path: Path) -> None:
        _init_repo(tmp_path)
        (tmp_path / "main.py").write_text("def add(a, b):\n    return a + b\n")
        _git(tmp_path, "add", "main.py")
        _git(tmp_path, "commit", "-m", "clean commit")
        findings = scan_history(tmp_path)
        assert findings == []
