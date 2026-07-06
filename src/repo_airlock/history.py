"""Git history scanning: a secret removed in a later commit still leaks.

Runs the content detectors against the *added* lines of every commit's diff,
including lines that were later deleted — because ``git log -p`` shows the
diff at each commit, a secret that appears in commit 3 and is removed in
commit 5 is still visible in commit 3's diff forever, for anyone who clones
the repo.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from repo_airlock.detectors import default_content_detectors
from repo_airlock.findings import Finding

_COMMIT_HEADER_RE = re.compile(r"^commit ([0-9a-f]{40})")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")


def is_git_repo(root: Path) -> bool:
    return (root / ".git").exists()


def _run_git_log(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "log", "-p", "--all", "--no-color", "--unified=0"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def scan_history(root: Path) -> list[Finding]:
    """Scan full git history for content that matches the secret/privacy detectors.

    Only inspects *added* lines (diff lines starting with a single ``+``) so we
    scan content that existed at some point in history, without re-flagging
    every unchanged line on every commit.
    """
    if not is_git_repo(root):
        return []

    log_output = _run_git_log(root)
    if not log_output:
        return []

    detectors = default_content_detectors()
    findings: list[Finding] = []

    current_commit = ""
    current_file = ""
    added_buffer: list[str] = []

    def flush() -> None:
        if not added_buffer or not current_file:
            return
        text = "\n".join(added_buffer)
        for detector in detectors:
            for f in detector.scan_text(current_file, text):
                findings.append(
                    Finding(
                        detector_id=f.detector_id,
                        severity=f.severity,
                        message=f.message,
                        path=f.path,
                        line=0,  # line numbers inside a diff hunk aren't meaningful across commits
                        match_redacted=f.match_redacted,
                        in_history=True,
                        commit=current_commit,
                    )
                )

    for line in log_output.splitlines():
        commit_match = _COMMIT_HEADER_RE.match(line)
        if commit_match:
            flush()
            added_buffer = []
            current_file = ""
            current_commit = commit_match.group(1)
            continue

        file_match = _DIFF_FILE_RE.match(line)
        if file_match:
            flush()
            added_buffer = []
            current_file = file_match.group(1)
            continue

        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+") and current_file:
            added_buffer.append(line[1:])

    flush()
    return findings
