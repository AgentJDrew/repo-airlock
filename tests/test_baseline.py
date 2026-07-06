"""Tests for baseline load/apply/write behavior."""

from __future__ import annotations

from pathlib import Path

from repo_airlock.baseline import apply_baseline, load_baseline, write_baseline
from repo_airlock.findings import Finding, Severity


def _finding(path: str = "f.py", line: int = 1, match: str = "AKIA...MPLE") -> Finding:
    return Finding(
        detector_id="secret-known-token:aws-access-key-id",
        severity=Severity.HIGH,
        message="AWS access key ID found",
        path=path,
        line=line,
        match_redacted=match,
    )


class TestBaseline:
    def test_load_missing_file_returns_empty_set(self, tmp_path: Path) -> None:
        assert load_baseline(tmp_path / "nope.json") == set()

    def test_write_then_load_roundtrip(self, tmp_path: Path) -> None:
        baseline_path = tmp_path / "baseline.json"
        findings = [_finding(), _finding(path="other.py", line=5)]
        write_baseline(baseline_path, findings)

        loaded = load_baseline(baseline_path)
        assert len(loaded) == 2
        assert findings[0].fingerprint() in loaded
        assert findings[1].fingerprint() in loaded

    def test_apply_baseline_suppresses_matching_finding(self) -> None:
        f1 = _finding()
        f2 = _finding(path="other.py")
        baseline = {f1.fingerprint()}

        kept, suppressed = apply_baseline([f1, f2], baseline)

        assert kept == [f2]
        assert suppressed == 1

    def test_apply_baseline_with_empty_set_keeps_everything(self) -> None:
        f1 = _finding()
        kept, suppressed = apply_baseline([f1], set())
        assert kept == [f1]
        assert suppressed == 0

    def test_apply_baseline_survives_commit_hash_change(self) -> None:
        """Fingerprint excludes commit so history findings stay suppressed post-rebase."""
        f1 = Finding(
            detector_id="secret-known-token:aws-access-key-id",
            severity=Severity.HIGH,
            message="AWS access key ID found",
            path="f.py",
            line=0,
            match_redacted="AKIA...MPLE",
            in_history=True,
            commit="a" * 40,
        )
        f2 = Finding(
            detector_id="secret-known-token:aws-access-key-id",
            severity=Severity.HIGH,
            message="AWS access key ID found",
            path="f.py",
            line=0,
            match_redacted="AKIA...MPLE",
            in_history=True,
            commit="b" * 40,
        )
        baseline = {f1.fingerprint()}
        kept, suppressed = apply_baseline([f2], baseline)
        assert kept == []
        assert suppressed == 1

    def test_load_baseline_handles_malformed_json(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not valid json")
        assert load_baseline(p) == set()
