"""Working-tree file discovery: what to scan and what to skip.

The guiding question for "what should be scanned" is: *what would actually
become public if this repo were pushed?* For a git repo, that's the tracked
files (respecting .gitignore) — not every byte sitting in the working
directory, which routinely includes venvs, node_modules, and build output
that were never going to be committed in the first place and would otherwise
drown the report in third-party-library false positives.

For a non-git directory (or as a fallback if git isn't available), we walk
the whole tree but still skip well-known dependency/VCS directories, since
scanning a vendored virtualenv's source code is never what the user wants.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

# Directories we never descend into during a plain filesystem walk — VCS
# internals plus the directories the hygiene detector calls out by name as
# "shouldn't ship." When git tracking data is available we rely on that
# instead (see iter_repo_files), so this list mainly matters for the
# non-git fallback path.
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".tox",
}

# Directory name *suffixes* to skip, for names that include a variable prefix
# (e.g. "repo_airlock.egg-info", "myapp.dist-info").
_SKIP_DIR_SUFFIXES = (".egg-info", ".dist-info")


def _should_skip_dir(name: str) -> bool:
    return name in _SKIP_DIRS or name.endswith(_SKIP_DIR_SUFFIXES)

# Binary/media extensions that are never worth scanning for text patterns.
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".mp3", ".mp4", ".mov", ".avi", ".wav",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".pyc",
    ".lock",  # package lockfiles are huge and low-signal for these checks
}

_MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024  # skip scanning content of files > 2MB (still checked for hygiene/size)


def _git_tracked_and_untracked_not_ignored(root: Path) -> list[str] | None:
    """Return git's view of "files that would ship": tracked files plus
    untracked-but-not-ignored files (new files you haven't committed yet are
    still about to become public the moment you `git add` + push).

    Returns None if this isn't a git repo or git isn't available, so callers
    can fall back to a plain filesystem walk.
    """
    if not (root / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    paths = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return sorted(paths)


def _walk_filesystem(root: Path) -> list[str]:
    results: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
        for fname in filenames:
            abs_path = Path(dirpath) / fname
            rel = abs_path.relative_to(root).as_posix()
            results.append(rel)
    return sorted(results)


def iter_repo_files(root: Path) -> list[str]:
    """Return all file paths under root (relative, POSIX-style) worth scanning.

    Prefers git's tracked+untracked-not-ignored file list (respects
    .gitignore, matching "what would actually go public"). Deliberately does
    NOT filter out dependency-looking directories in this branch: if
    node_modules/ or a venv really is tracked by git (the exact mistake the
    hygiene detector's "tracked junk dir" check exists to catch), we need to
    see it. Falls back to a plain filesystem walk — which DOES skip VCS/
    dependency directories, since there's no .gitignore signal to rely on —
    when the target isn't a git repository at all.
    """
    git_files = _git_tracked_and_untracked_not_ignored(root)
    if git_files is not None:
        return [p for p in git_files if not any(part in {".git", ".hg", ".svn"} for part in Path(p).parts)]
    return _walk_filesystem(root)


def is_scannable_text_file(abs_path: Path) -> bool:
    """Whether we should read this file's content for the text-based detectors."""
    if abs_path.suffix.lower() in _SKIP_EXTENSIONS:
        return False
    try:
        if abs_path.stat().st_size > _MAX_TEXT_FILE_BYTES:
            return False
        if abs_path.stat().st_size == 0:
            return False
    except OSError:
        return False
    return True


def read_text_safely(abs_path: Path) -> str | None:
    """Read a file as text, returning None if it looks binary or can't be read."""
    try:
        raw = abs_path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None  # null byte in the first chunk -> treat as binary
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except UnicodeDecodeError:
            return None
