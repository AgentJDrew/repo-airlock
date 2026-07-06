"""Publication hygiene: the non-secret reasons a repo isn't ready to be public."""

from __future__ import annotations

from pathlib import Path

from repo_airlock.findings import Finding, Severity

_LARGE_FILE_THRESHOLD_BYTES = 5 * 1024 * 1024  # 5MB

_TRACKED_JUNK_DIR_NAMES = {
    "node_modules",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    "__pycache__",
    ".tox",
    "target",  # rust/java build output
    "site-packages",
}

_README_NAMES = ["README.md", "README.rst", "README.txt", "README"]
_LICENSE_NAMES = ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]

_STUB_README_MAX_CHARS = 80


class HygieneDetector:
    """Filesystem-level checks that run once over the whole tree (not per-file)."""

    id = "hygiene"
    severity = Severity.LOW

    def scan_repo(self, root: Path, all_rel_paths: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_license(root))
        findings.extend(self._check_readme(root))
        findings.extend(self._check_gitignore(root))
        findings.extend(self._check_tracked_junk_dirs(all_rel_paths))
        findings.extend(self._check_large_files(root, all_rel_paths))
        return findings

    def _check_license(self, root: Path) -> list[Finding]:
        if any((root / name).is_file() for name in _LICENSE_NAMES):
            return []
        return [
            Finding(
                detector_id=f"{self.id}:missing-license",
                severity=Severity.MEDIUM,
                message="no LICENSE file found — repo has no explicit open-source license",
                path=".",
                line=0,
            )
        ]

    def _check_readme(self, root: Path) -> list[Finding]:
        readme_path = next((root / name for name in _README_NAMES if (root / name).is_file()), None)
        if readme_path is None:
            return [
                Finding(
                    detector_id=f"{self.id}:missing-readme",
                    severity=Severity.MEDIUM,
                    message="no README file found",
                    path=".",
                    line=0,
                )
            ]
        try:
            content = readme_path.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            return []
        if len(content) < _STUB_README_MAX_CHARS:
            return [
                Finding(
                    detector_id=f"{self.id}:stub-readme",
                    severity=Severity.LOW,
                    message=(
                        f"README looks like a stub ({len(content)} chars) — "
                        "add a real description before publishing"
                    ),
                    path=readme_path.name,
                    line=0,
                )
            ]
        return []

    def _check_gitignore(self, root: Path) -> list[Finding]:
        if (root / ".gitignore").is_file():
            return []
        return [
            Finding(
                detector_id=f"{self.id}:missing-gitignore",
                severity=Severity.LOW,
                message="no .gitignore found — increases risk of accidentally committing junk/secrets",
                path=".",
                line=0,
            )
        ]

    def _check_tracked_junk_dirs(self, all_rel_paths: list[str]) -> list[Finding]:
        seen: set[str] = set()
        findings: list[Finding] = []
        for rel in all_rel_paths:
            parts = Path(rel).parts
            for part in parts[:-1]:
                if part in _TRACKED_JUNK_DIR_NAMES and part not in seen:
                    seen.add(part)
                    findings.append(
                        Finding(
                            detector_id=f"{self.id}:tracked-junk-dir",
                            severity=Severity.MEDIUM,
                            message=f"'{part}/' appears to be tracked — dependency/build output shouldn't ship in the repo",
                            path=part,
                            line=0,
                        )
                    )
        return findings

    def _check_large_files(self, root: Path, all_rel_paths: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for rel in all_rel_paths:
            abs_path = root / rel
            try:
                size = abs_path.stat().st_size
            except OSError:
                continue
            if size > _LARGE_FILE_THRESHOLD_BYTES:
                mb = size / (1024 * 1024)
                findings.append(
                    Finding(
                        detector_id=f"{self.id}:large-binary",
                        severity=Severity.LOW,
                        message=f"tracked file is {mb:.1f}MB — consider Git LFS or removing it",
                        path=rel,
                        line=0,
                    )
                )
        return findings
