"""Detector implementations for repo-airlock.

Content detectors (secrets, privacy) implement ``scan_text(path, text)`` and
run against both working-tree files and git history diffs. Path/tree
detectors (cred_files, hygiene) implement filesystem-aware methods and only
run against the working tree.
"""

from repo_airlock.detectors.cred_files import CredentialFileDetector
from repo_airlock.detectors.hygiene import HygieneDetector
from repo_airlock.detectors.privacy import default_privacy_detectors
from repo_airlock.detectors.secrets import default_secret_detectors

__all__ = [
    "CredentialFileDetector",
    "HygieneDetector",
    "default_privacy_detectors",
    "default_secret_detectors",
]


def default_content_detectors() -> list:
    """Detectors that scan raw text content (files or history diffs)."""
    return [*default_secret_detectors(), *default_privacy_detectors()]
