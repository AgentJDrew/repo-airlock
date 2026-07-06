"""Report rendering: console (default), markdown, and json formats."""

from __future__ import annotations

import json

from repo_airlock.findings import Finding, ScanResult, Severity

_SEVERITY_LABEL = {
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
}

_USE_COLOR_CODES = {
    Severity.HIGH: "\033[91m",   # red
    Severity.MEDIUM: "\033[93m",  # yellow
    Severity.LOW: "\033[94m",     # blue
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _group_by_severity(findings: list[Finding]) -> dict[Severity, list[Finding]]:
    groups: dict[Severity, list[Finding]] = {Severity.HIGH: [], Severity.MEDIUM: [], Severity.LOW: []}
    for f in findings:
        groups[f.severity].append(f)
    return groups


def render_console(result: ScanResult, *, fail_on: Severity, use_color: bool = True) -> str:
    lines: list[str] = []
    groups = _group_by_severity(result.findings)

    def c(sev: Severity, text: str) -> str:
        if not use_color:
            return text
        return f"{_USE_COLOR_CODES[sev]}{text}{_RESET}"

    def bold(text: str) -> str:
        return f"{_BOLD}{text}{_RESET}" if use_color else text

    lines.append(bold("repo-airlock scan report"))
    lines.append("=" * 40)

    if not result.findings:
        lines.append("")
        lines.append("No findings. Nothing to report.")
    else:
        for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            items = groups[sev]
            if not items:
                continue
            lines.append("")
            lines.append(c(sev, bold(f"[{_SEVERITY_LABEL[sev]}] ({len(items)})")))
            for f in items:
                loc = f.location()
                extra = f" — {f.match_redacted}" if f.match_redacted else ""
                lines.append(f"  {loc}  {f.message}{extra}")

    counts = result.counts_by_severity()
    lines.append("")
    lines.append("-" * 40)
    lines.append(
        f"Scanned {result.files_scanned} file(s)"
        + (" + full git history" if result.history_scanned else "")
        + f". Findings: HIGH={counts[Severity.HIGH]} MEDIUM={counts[Severity.MEDIUM]} LOW={counts[Severity.LOW]}"
    )
    if result.suppressed_count:
        lines.append(f"({result.suppressed_count} finding(s) suppressed by baseline)")

    if any(f.in_history for f in result.findings):
        lines.append("")
        lines.append(
            "NOTE: some findings exist only in git history. Removing the file today "
            "does NOT remove it from history — anyone who clones the repo can still "
            "recover it. Recommended: rewrite history (git filter-repo / BFG) to purge "
            "the blobs, or publish a fresh repo from a clean history instead."
        )

    verdict = result.verdict(fail_on)
    lines.append("")
    verdict_line = f"VERDICT: {verdict}"
    if use_color:
        color = "\033[92m" if verdict == "CLEARED" else "\033[91m"
        verdict_line = f"{_BOLD}{color}{verdict_line}{_RESET}"
    lines.append(verdict_line)

    return "\n".join(lines)


def render_markdown(result: ScanResult, *, fail_on: Severity) -> str:
    lines: list[str] = ["# repo-airlock scan report", ""]
    counts = result.counts_by_severity()
    verdict = result.verdict(fail_on)

    lines.append(f"**Verdict:** {verdict}")
    lines.append("")
    lines.append(
        f"Scanned {result.files_scanned} file(s)"
        + (" + full git history" if result.history_scanned else "")
        + "."
    )
    lines.append("")
    lines.append(f"| Severity | Count |\n|---|---|\n| HIGH | {counts[Severity.HIGH]} |\n"
                  f"| MEDIUM | {counts[Severity.MEDIUM]} |\n| LOW | {counts[Severity.LOW]} |")

    if result.suppressed_count:
        lines.append("")
        lines.append(f"_{result.suppressed_count} finding(s) suppressed by baseline._")

    groups = _group_by_severity(result.findings)
    for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        items = groups[sev]
        if not items:
            continue
        lines.append("")
        lines.append(f"## {_SEVERITY_LABEL[sev]} ({len(items)})")
        lines.append("")
        lines.append("| Location | Detector | Message | Match |")
        lines.append("|---|---|---|---|")
        for f in items:
            lines.append(f"| `{f.location()}` | `{f.detector_id}` | {f.message} | `{f.match_redacted}` |")

    if any(f.in_history for f in result.findings):
        lines.append("")
        lines.append(
            "> **Note:** some findings exist only in git history. Deleting the file today "
            "does not remove it from history. Consider a history rewrite (git filter-repo / "
            "BFG) or publishing from a fresh history."
        )

    return "\n".join(lines) + "\n"


def render_json(result: ScanResult, *, fail_on: Severity) -> str:
    payload = {
        "verdict": result.verdict(fail_on),
        "files_scanned": result.files_scanned,
        "history_scanned": result.history_scanned,
        "suppressed_count": result.suppressed_count,
        "counts": {str(k): v for k, v in result.counts_by_severity().items()},
        "findings": [
            {
                "detector_id": f.detector_id,
                "severity": str(f.severity),
                "message": f.message,
                "path": f.path,
                "line": f.line,
                "match_redacted": f.match_redacted,
                "in_history": f.in_history,
                "commit": f.commit,
                "fingerprint": f.fingerprint(),
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2) + "\n"
