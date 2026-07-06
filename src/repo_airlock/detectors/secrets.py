"""Secret detectors: known token formats + generic assignment + entropy."""

from __future__ import annotations

import math
import re

from repo_airlock.findings import Finding, Severity
from repo_airlock.redact import redact

# --- Known token formats -----------------------------------------------

_KNOWN_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("aws-access-key-id", "AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "aws-secret-key",
        "possible AWS secret access key (40-char base64-ish string near 'aws')",
        re.compile(r"\baws(?:_|-)?secret(?:_|-)?(?:access_)?key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE),
    ),
    ("github-token", "GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-pat", "GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack-token", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live-key", "Stripe live secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("stripe-live-restricted", "Stripe live restricted key", re.compile(r"\brk_live_[A-Za-z0-9]{16,}\b")),
    ("google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "jwt",
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "pem-private-key",
        "PEM private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    ("slack-webhook", "Slack incoming webhook URL", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{20,}")),
]

# Generic `password = "..."` / `api_key: '...'` style assignments.
_GENERIC_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<key>password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)
    \b\s*[:=]\s*
    (?P<quote>['"])(?P<value>(?!\s*$|\{|\$|%|<).{4,200}?)(?P=quote)
    """
)

# Placeholders we should never flag from the generic-assignment or entropy checks.
# Matched as a substring search (not full-match) since real placeholders are
# often embedded in a slightly longer phrase, e.g. "your-api-key-here" or
# "insert-secret-here-please".
_PLACEHOLDER_RE = re.compile(
    r"^(?:x{3,}|\*{3,}|-{3,})$|"
    r"change[_-]?me|your[_-]?(?:api[_-]?)?key|"
    r"placeholder|example|dummy|fake|todo|fixme|"
    r"^<[^>]+>$|^\{\{.*\}\}$|^\$\{.*\}$|"
    r"^test[_-]?(?:key|secret|token|password|value)?$",
    re.IGNORECASE,
)

_MIN_ENTROPY_LEN = 20
_MAX_ENTROPY_LEN = 200
_ENTROPY_STRING_RE = re.compile(r"""['"]([A-Za-z0-9+/_=\-\.]{20,200})['"]""")


def _looks_like_placeholder(value: str) -> bool:
    stripped = value.strip().strip("'\"")
    if not stripped:
        return True
    if _PLACEHOLDER_RE.search(stripped):
        return True
    # Values that are all the same character, or look like a UUID of zeros, etc.
    if len(set(stripped)) <= 2:
        return True
    return False


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. Higher = more random-looking."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class KnownTokenDetector:
    """Regex matches against well-known secret token formats."""

    id = "secret-known-token"
    severity = Severity.HIGH

    def scan_text(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for token_id, description, pattern in _KNOWN_PATTERNS:
                for m in pattern.finditer(line):
                    matched = m.group(0)
                    findings.append(
                        Finding(
                            detector_id=f"{self.id}:{token_id}",
                            severity=self.severity,
                            message=f"{description} found",
                            path=path,
                            line=lineno,
                            match_redacted=redact(matched),
                        )
                    )
        return findings


class GenericAssignmentDetector:
    """Catches hardcoded credential-assignment style secrets that the named
    token patterns can't recognize (e.g. an arbitrary internal API key)."""

    id = "secret-generic-assignment"
    severity = Severity.MEDIUM

    def scan_text(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for m in _GENERIC_ASSIGNMENT.finditer(line):
                value = m.group("value")
                if _looks_like_placeholder(value):
                    continue
                key = m.group("key")
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=self.severity,
                        message=f"hardcoded value assigned to '{key}'",
                        path=path,
                        line=lineno,
                        match_redacted=redact(value),
                    )
                )
        return findings


class EntropyDetector:
    """Flags long, high-entropy string literals — catches unknown token formats.

    Deliberately conservative: long length floor + high entropy threshold to
    limit false positives on things like base64 fixtures, hashes used as test
    data, or hex color tables. This is a net for the *unknown* token formats
    the named-pattern detector can't catch by design.
    """

    id = "secret-high-entropy-string"
    severity = Severity.LOW
    threshold = 4.3  # bits/char; random base64/hex tokens land ~4.5-6.0

    def scan_text(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            # Skip lines already caught by more specific detectors to avoid noise.
            for m in _ENTROPY_STRING_RE.finditer(line):
                value = m.group(1)
                if _looks_like_placeholder(value):
                    continue
                if not (_MIN_ENTROPY_LEN <= len(value) <= _MAX_ENTROPY_LEN):
                    continue
                entropy = shannon_entropy(value)
                if entropy < self.threshold:
                    continue
                # Require a mix of char classes to cut down on false positives
                # from long English words/URLs/paths that happen to be long.
                has_digit = any(c.isdigit() for c in value)
                has_alpha = any(c.isalpha() for c in value)
                has_upper = any(c.isupper() for c in value)
                has_lower = any(c.islower() for c in value)
                class_score = sum([has_digit, has_alpha, has_upper, has_lower])
                if class_score < 3:
                    continue
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=self.severity,
                        message=(
                            f"high-entropy string literal ({entropy:.1f} bits/char) "
                            "resembles an undetected token/secret"
                        ),
                        path=path,
                        line=lineno,
                        match_redacted=redact(value),
                    )
                )
        return findings


def default_secret_detectors() -> list:
    return [KnownTokenDetector(), GenericAssignmentDetector(), EntropyDetector()]
