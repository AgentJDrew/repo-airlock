"""Core data types shared by every detector."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so comparisons like ``severity >= Severity.HIGH`` work."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(
                f"invalid severity {value!r}; expected one of low, medium, high"
            ) from exc

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass(frozen=True)
class Finding:
    """A single issue surfaced by a detector.

    ``match_redacted`` must never contain the full sensitive value — detectors
    are responsible for redacting before constructing a Finding.
    """

    detector_id: str
    severity: Severity
    message: str
    path: str
    line: int = 0
    match_redacted: str = ""
    in_history: bool = False
    commit: str = ""

    def fingerprint(self) -> str:
        """Stable identity used for baseline suppression.

        Deliberately excludes ``commit`` so a baseline entry keeps suppressing
        a historical finding even if it shows up under a different commit hash
        (e.g. after a rebase) as long as path/line/detector/match line up.
        """
        return f"{self.detector_id}:{self.path}:{self.line}:{self.match_redacted}"

    def location(self) -> str:
        if self.in_history:
            commit_short = self.commit[:8] if self.commit else "?"
            return f"{self.path}:{self.line} (history @ {commit_short})"
        return f"{self.path}:{self.line}"


@dataclass
class ScanResult:
    """Aggregated output of a full scan run."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    history_scanned: bool = False
    suppressed_count: int = 0

    def counts_by_severity(self) -> dict[Severity, int]:
        counts = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def verdict(self, fail_on: Severity = Severity.LOW) -> str:
        top = self.max_severity()
        if top is None:
            return "CLEARED"
        if top >= fail_on:
            return "HOLD"
        return "CLEARED"

    def exit_code(self, fail_on: Severity) -> int:
        top = self.max_severity()
        if top is not None and top >= fail_on:
            return 1
        return 0
