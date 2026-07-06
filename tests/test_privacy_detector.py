"""Tests for the privacy/identity detectors."""

from __future__ import annotations

from repo_airlock.detectors.privacy import (
    EmailDetector,
    InternalHostnameDetector,
    PhoneNumberDetector,
    PrivateIPDetector,
    UserPathDetector,
)
from repo_airlock.findings import Severity


class TestEmailDetector:
    def setup_method(self) -> None:
        self.detector = EmailDetector()

    def test_flags_real_looking_email(self) -> None:
        findings = self.detector.scan_text("f.txt", 'contact = "jane.doe.testfixture@gmail.com"')
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_ignores_example_domain(self) -> None:
        findings = self.detector.scan_text("f.txt", 'contact = "someone@example.com"')
        assert findings == []

    def test_ignores_github_noreply(self) -> None:
        findings = self.detector.scan_text("f.txt", "author@users.noreply.github.com")
        assert findings == []


class TestPhoneNumberDetector:
    def setup_method(self) -> None:
        self.detector = PhoneNumberDetector()

    def test_flags_dashed_phone(self) -> None:
        findings = self.detector.scan_text("f.txt", 'phone = "555-201-3948"')
        assert len(findings) == 1

    def test_flags_parenthesized_phone(self) -> None:
        findings = self.detector.scan_text("f.txt", "call (555) 201-3948 now")
        assert len(findings) == 1

    def test_ignores_short_number_sequences(self) -> None:
        findings = self.detector.scan_text("f.txt", "version 1.2.3-4567 build 89")
        assert findings == []


class TestUserPathDetector:
    def setup_method(self) -> None:
        self.detector = UserPathDetector()

    def test_flags_windows_user_path(self) -> None:
        findings = self.detector.scan_text("f.txt", r"C:\Users\jdoe_fixture\Desktop\project")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_flags_mac_user_path(self) -> None:
        findings = self.detector.scan_text("f.txt", "/Users/jdoe_fixture/projects/app")
        assert len(findings) == 1

    def test_flags_linux_user_path(self) -> None:
        findings = self.detector.scan_text("f.txt", "/home/jdoe_fixture/app")
        assert len(findings) == 1

    def test_ignores_generic_placeholder_username(self) -> None:
        findings = self.detector.scan_text("f.txt", r"C:\Users\username\Desktop")
        assert findings == []

    def test_ignores_ci_runner_path(self) -> None:
        findings = self.detector.scan_text("f.txt", "/home/runner/work/repo")
        assert findings == []


class TestInternalHostnameDetector:
    def setup_method(self) -> None:
        self.detector = InternalHostnameDetector()

    def test_flags_dot_internal(self) -> None:
        findings = self.detector.scan_text("f.txt", "connect to db01.internal for staging")
        assert len(findings) == 1

    def test_flags_dot_corp(self) -> None:
        findings = self.detector.scan_text("f.txt", "host: build.corp")
        assert len(findings) == 1

    def test_ignores_public_domain(self) -> None:
        findings = self.detector.scan_text("f.txt", "visit example.com for details")
        assert findings == []


class TestPrivateIPDetector:
    def setup_method(self) -> None:
        self.detector = PrivateIPDetector()

    def test_flags_10_range(self) -> None:
        findings = self.detector.scan_text("f.txt", "server at 10.0.5.12")
        assert len(findings) == 1
        assert "10.0.0.0/8" in findings[0].message

    def test_flags_172_16_range(self) -> None:
        findings = self.detector.scan_text("f.txt", "server at 172.16.4.9")
        assert len(findings) == 1

    def test_ignores_172_out_of_range(self) -> None:
        # 172.32.x.x is NOT in the 172.16.0.0/12 private range.
        findings = self.detector.scan_text("f.txt", "server at 172.32.4.9")
        assert findings == []

    def test_flags_192_168_range(self) -> None:
        findings = self.detector.scan_text("f.txt", "server at 192.168.1.50")
        assert len(findings) == 1

    def test_flags_tailscale_cgnat_range(self) -> None:
        findings = self.detector.scan_text("f.txt", "tailscale ip 100.64.0.42")
        assert len(findings) == 1
        assert "100.64.0.0/10" in findings[0].message

    def test_ignores_public_ip(self) -> None:
        findings = self.detector.scan_text("f.txt", "dns server 8.8.8.8")
        assert findings == []

    def test_ignores_loopback(self) -> None:
        findings = self.detector.scan_text("f.txt", "localhost is 127.0.0.1")
        assert findings == []
