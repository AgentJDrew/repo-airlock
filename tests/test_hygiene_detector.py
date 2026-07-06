"""Tests for the publication hygiene detector."""

from __future__ import annotations

from pathlib import Path

from repo_airlock.detectors.hygiene import HygieneDetector


class TestHygieneDetector:
    def setup_method(self) -> None:
        self.detector = HygieneDetector()

    def test_flags_missing_license(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text(
            "# A real project\n\nWith enough content to not be considered a stub README file."
        )
        findings = self.detector.scan_repo(tmp_path, ["README.md"])
        assert any("missing-license" in f.detector_id for f in findings)

    def test_flags_missing_readme(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("MIT License")
        findings = self.detector.scan_repo(tmp_path, ["LICENSE"])
        assert any("missing-readme" in f.detector_id for f in findings)

    def test_flags_stub_readme(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("TODO")
        (tmp_path / "LICENSE").write_text("MIT License " * 20)
        findings = self.detector.scan_repo(tmp_path, ["README.md", "LICENSE"])
        assert any("stub-readme" in f.detector_id for f in findings)

    def test_flags_missing_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# A real project\n\nWith enough content to not be a stub.")
        (tmp_path / "LICENSE").write_text("MIT License")
        findings = self.detector.scan_repo(tmp_path, ["README.md", "LICENSE"])
        assert any("missing-gitignore" in f.detector_id for f in findings)

    def test_flags_tracked_node_modules(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# A real project\n\nWith enough content to not be a stub.")
        (tmp_path / "LICENSE").write_text("MIT License")
        (tmp_path / ".gitignore").write_text("*.pyc")
        rel_paths = ["README.md", "LICENSE", ".gitignore", "node_modules/pkg/index.js"]
        findings = self.detector.scan_repo(tmp_path, rel_paths)
        assert any("tracked-junk-dir" in f.detector_id for f in findings)

    def test_flags_large_binary(self, tmp_path: Path) -> None:
        big_file = tmp_path / "big.bin"
        big_file.write_bytes(b"0" * (6 * 1024 * 1024))
        (tmp_path / "README.md").write_text("# A real project\n\nWith enough content to not be a stub.")
        (tmp_path / "LICENSE").write_text("MIT License")
        (tmp_path / ".gitignore").write_text("*.pyc")
        rel_paths = ["README.md", "LICENSE", ".gitignore", "big.bin"]
        findings = self.detector.scan_repo(tmp_path, rel_paths)
        assert any("large-binary" in f.detector_id for f in findings)

    def test_clean_repo_has_no_findings(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text(
            "# A real project\n\n"
            "With enough content in this README file to not be considered a stub by the hygiene check."
        )
        (tmp_path / "LICENSE").write_text("MIT License " * 20)
        (tmp_path / ".gitignore").write_text("*.pyc\n__pycache__/\n")
        rel_paths = ["README.md", "LICENSE", ".gitignore"]
        findings = self.detector.scan_repo(tmp_path, rel_paths)
        assert findings == []
