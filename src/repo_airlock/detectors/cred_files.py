"""Detects credential-shaped files that should never be tracked in git."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from repo_airlock.findings import Finding, Severity

# Glob patterns matched against the file's basename.
_NAME_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.pfx",
    "*.p12",
    "*.key",
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "id_dsa",
    "id_dsa.*",
    ".netrc",
    "_netrc",
    "credentials",
    "credentials.json",
    ".pgpass",
    "*.kdbx",
]

_ALWAYS_SUSPECT_NAMES = {
    ".env",
    ".netrc",
    "_netrc",
    "credentials",
    "id_rsa",
    "id_ed25519",
    "id_dsa",
    ".pgpass",
}


class CredentialFileDetector:
    """Flags files whose *name* strongly suggests credential material.

    Also inspects small JSON files for a ``"private_key"`` field, which is the
    signature of a cloud service-account key regardless of filename.
    """

    id = "cred-file"
    severity = Severity.HIGH

    def scan_path(self, root: Path, rel_path: str, abs_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        name = abs_path.name

        for pattern in _NAME_PATTERNS:
            if fnmatch.fnmatch(name.lower(), pattern.lower()) or name in _ALWAYS_SUSPECT_NAMES:
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=self.severity,
                        message=f"file name '{name}' matches a known credential-file pattern",
                        path=rel_path,
                        line=0,
                        match_redacted=name,
                    )
                )
                break  # one finding per file is enough for name matches

        if name.lower().endswith(".json"):
            finding = self._check_service_account_json(rel_path, abs_path)
            if finding is not None:
                findings.append(finding)

        return findings

    def _check_service_account_json(self, rel_path: str, abs_path: Path) -> Finding | None:
        try:
            if abs_path.stat().st_size > 1_000_000:
                return None
            content = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        if '"private_key"' in content and '"type"' in content:
            return Finding(
                detector_id=f"{self.id}:service-account-json",
                severity=Severity.HIGH,
                message="JSON file contains a 'private_key' field — looks like a cloud service-account key",
                path=rel_path,
                line=0,
                match_redacted=abs_path.name,
            )
        return None
