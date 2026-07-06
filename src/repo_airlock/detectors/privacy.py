"""Privacy/identity leak detectors: emails, phone numbers, local usernames,
internal hostnames, and private/CGNAT IP ranges.

These are the checks gitleaks/trufflehog do NOT do — they're not secrets in
the credential sense, but they leak who you are, where you work, or what your
internal network looks like, which is exactly what you don't want in a repo
you're about to make public.
"""

from __future__ import annotations

import ipaddress
import re

from repo_airlock.findings import Finding, Severity
from repo_airlock.redact import redact

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Common placeholder/example domains and addresses we don't want to flag.
_EMAIL_ALLOWLIST_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "domain.com",
    "yourdomain.com",
    "email.com",
    "users.noreply.github.com",
}

_PHONE_RE = re.compile(
    r"""(?<![\w.])
    (?:\+?1[-.\s]?)?
    \(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}
    (?![\w])
    """,
    re.VERBOSE,
)

# Windows: C:\Users\<name>\...   Mac: /Users/<name>/...   Linux: /home/<name>/...
_WIN_USER_PATH_RE = re.compile(r"[A-Za-z]:\\Users\\([^\\/\s\"'<>|]+)")
_MAC_USER_PATH_RE = re.compile(r"/Users/([^/\s\"'<>|]+)")
_LINUX_USER_PATH_RE = re.compile(r"/home/([^/\s\"'<>|]+)")

_GENERIC_USER_PLACEHOLDERS = {
    "username", "user", "youruser", "yourname", "name", "public",
    "default", "shared", "guest", "runner", "builder", "ci",
}

# Internal-looking hostnames, e.g. a machine name ending in .internal/.corp/.local
_INTERNAL_HOSTNAME_RE = re.compile(
    r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|corp|local|lan|intranet|home\.arpa)\b",
    re.IGNORECASE,
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _is_private_or_special_ip(ip_str: str) -> str | None:
    """Return a short reason string if the IP is private/CGNAT, else None."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return None  # not interesting for this check
    # RFC1918 handled by is_private, but is_private also covers CGNAT etc. Be explicit
    # so the message is specific and we can unit test each range independently.
    if ip in ipaddress.ip_network("10.0.0.0/8"):
        return "RFC1918 private IP (10.0.0.0/8)"
    if ip in ipaddress.ip_network("172.16.0.0/12"):
        return "RFC1918 private IP (172.16.0.0/12)"
    if ip in ipaddress.ip_network("192.168.0.0/16"):
        return "RFC1918 private IP (192.168.0.0/16)"
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return "CGNAT range (100.64.0.0/10) — commonly used by Tailscale/carrier-NAT"
    return None


class EmailDetector:
    id = "privacy-email"
    severity = Severity.LOW

    def scan_text(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _EMAIL_RE.finditer(line):
                email = m.group(0)
                domain = email.rsplit("@", 1)[-1].lower()
                if domain in _EMAIL_ALLOWLIST_DOMAINS:
                    continue
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=self.severity,
                        message="email address found",
                        path=path,
                        line=lineno,
                        match_redacted=redact(email),
                    )
                )
        return findings


class PhoneNumberDetector:
    id = "privacy-phone-number"
    severity = Severity.LOW

    def scan_text(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _PHONE_RE.finditer(line):
                digits = re.sub(r"\D", "", m.group(0))
                if len(digits) < 10:
                    continue
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=self.severity,
                        message="phone-number-shaped string found",
                        path=path,
                        line=lineno,
                        match_redacted=redact(m.group(0)),
                    )
                )
        return findings


class UserPathDetector:
    """Absolute local paths leak the OS username of whoever built the repo."""

    id = "privacy-user-path"
    severity = Severity.MEDIUM

    def scan_text(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, kind in (
                (_WIN_USER_PATH_RE, "Windows"),
                (_MAC_USER_PATH_RE, "macOS"),
                (_LINUX_USER_PATH_RE, "Linux"),
            ):
                for m in pattern.finditer(line):
                    username = m.group(1)
                    if username.lower() in _GENERIC_USER_PLACEHOLDERS:
                        continue
                    # A real username segment doesn't contain regex metacharacters;
                    # this guards against matching a regex pattern's own source
                    # (e.g. a character class like "([^...]+)" showing up right
                    # after "/Users/" in a detector's own code).
                    if any(ch in username for ch in "()[]^$*+?{}|\\"):
                        continue
                    findings.append(
                        Finding(
                            detector_id=self.id,
                            severity=self.severity,
                            message=f"absolute {kind} user path leaks local username",
                            path=path,
                            line=lineno,
                            match_redacted=redact(m.group(0)),
                        )
                    )
        return findings


class InternalHostnameDetector:
    id = "privacy-internal-hostname"
    severity = Severity.LOW

    def scan_text(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _INTERNAL_HOSTNAME_RE.finditer(line):
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=self.severity,
                        message="internal-looking hostname found",
                        path=path,
                        line=lineno,
                        match_redacted=redact(m.group(0)),
                    )
                )
        return findings


class PrivateIPDetector:
    id = "privacy-private-ip"
    severity = Severity.MEDIUM

    def scan_text(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _IPV4_RE.finditer(line):
                reason = _is_private_or_special_ip(m.group(0))
                if reason is None:
                    continue
                findings.append(
                    Finding(
                        detector_id=self.id,
                        severity=self.severity,
                        message=f"private IP address found ({reason})",
                        path=path,
                        line=lineno,
                        match_redacted=redact(m.group(0)),
                    )
                )
        return findings


def default_privacy_detectors() -> list:
    return [
        EmailDetector(),
        PhoneNumberDetector(),
        UserPathDetector(),
        InternalHostnameDetector(),
        PrivateIPDetector(),
    ]
