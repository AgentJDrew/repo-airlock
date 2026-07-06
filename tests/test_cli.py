"""Tests for the CLI: exit codes, formats, baseline flags."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_airlock.cli import main


def _make_dirty_repo(tmp_path: Path) -> Path:
    (tmp_path / "README.md").write_text(
        "# Real project\n\nThis README has enough content in it to not be considered a stub file by the hygiene check."
    )
    (tmp_path / "LICENSE").write_text("MIT License " * 10)
    (tmp_path / ".gitignore").write_text("*.pyc\n")
    (tmp_path / "config.py").write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
    return tmp_path


def _make_clean_repo(tmp_path: Path) -> Path:
    (tmp_path / "README.md").write_text(
        "# Real project\n\nThis README has enough content in it to not be considered a stub file by the hygiene check."
    )
    (tmp_path / "LICENSE").write_text("MIT License " * 10)
    (tmp_path / ".gitignore").write_text("*.pyc\n")
    (tmp_path / "main.py").write_text("def add(a, b):\n    return a + b\n")
    return tmp_path


class TestCLI:
    def test_scan_dirty_repo_exits_nonzero_at_default_threshold(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        root = _make_dirty_repo(tmp_path)
        exit_code = main(["scan", str(root), "--no-color"])
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "HOLD" in captured.out

    def test_scan_clean_repo_exits_zero(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        root = _make_clean_repo(tmp_path)
        exit_code = main(["scan", str(root), "--no-color"])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "CLEARED" in captured.out

    def test_fail_on_low_makes_low_severity_fail(self, tmp_path: Path) -> None:
        root = _make_clean_repo(tmp_path)
        (root / "notes.txt").write_text("contact someone@notexample.org for help")
        exit_code = main(["scan", str(root), "--fail-on", "low", "--no-color"])
        assert exit_code == 1

    def test_json_format_is_valid_json(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        root = _make_dirty_repo(tmp_path)
        main(["scan", str(root), "--format", "json"])
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["verdict"] == "HOLD"
        assert isinstance(payload["findings"], list)
        assert len(payload["findings"]) > 0

    def test_json_never_leaks_full_secret(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        root = _make_dirty_repo(tmp_path)
        main(["scan", str(root), "--format", "json"])
        captured = capsys.readouterr()
        assert "AKIAIOSFODNN7EXAMPLE" not in captured.out

    def test_markdown_format_has_header(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        root = _make_dirty_repo(tmp_path)
        main(["scan", str(root), "--format", "md"])
        captured = capsys.readouterr()
        assert captured.out.startswith("# repo-airlock scan report")

    def test_write_baseline_then_rescan_clears(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        root = _make_dirty_repo(tmp_path)
        baseline_path = tmp_path.parent / "baseline.json"

        exit_code = main(["scan", str(root), "--write-baseline", str(baseline_path)])
        assert exit_code == 0
        assert baseline_path.is_file()

        capsys.readouterr()
        exit_code = main(["scan", str(root), "--baseline", str(baseline_path), "--no-color"])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "CLEARED" in captured.out

    def test_nonexistent_path_errors(self, tmp_path: Path) -> None:
        exit_code = main(["scan", str(tmp_path / "does-not-exist")])
        assert exit_code == 2

    def test_version_flag(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
