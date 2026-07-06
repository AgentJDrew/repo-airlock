"""Orchestrates a full scan: working tree + optional history + hygiene."""

from __future__ import annotations

from pathlib import Path

from repo_airlock.baseline import apply_baseline, load_baseline
from repo_airlock.detectors import CredentialFileDetector, HygieneDetector, default_content_detectors
from repo_airlock.findings import ScanResult
from repo_airlock.history import scan_history
from repo_airlock.walker import is_scannable_text_file, iter_repo_files, read_text_safely


def scan(
    root: Path,
    *,
    include_history: bool = False,
    baseline_path: Path | None = None,
) -> ScanResult:
    root = root.resolve()
    all_rel_paths = iter_repo_files(root)

    content_detectors = default_content_detectors()
    cred_file_detector = CredentialFileDetector()
    hygiene_detector = HygieneDetector()

    result = ScanResult()
    files_scanned = 0

    for rel_path in all_rel_paths:
        abs_path = root / rel_path

        # Filesystem-shape checks (filename/content-signature based, not text-pattern based).
        result.findings.extend(cred_file_detector.scan_path(root, rel_path, abs_path))

        if not is_scannable_text_file(abs_path):
            continue
        text = read_text_safely(abs_path)
        if text is None:
            continue

        files_scanned += 1
        for detector in content_detectors:
            result.findings.extend(detector.scan_text(rel_path, text))

    result.files_scanned = files_scanned
    result.findings.extend(hygiene_detector.scan_repo(root, all_rel_paths))

    if include_history:
        result.findings.extend(scan_history(root))
        result.history_scanned = True

    if baseline_path is not None:
        kept, suppressed = apply_baseline(result.findings, load_baseline(baseline_path))
        result.findings = kept
        result.suppressed_count = suppressed

    # Stable, readable ordering: worst severity first, then path, then line.
    result.findings.sort(key=lambda f: (-int(f.severity), f.path, f.line))

    return result
