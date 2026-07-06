"""Tests for the credential-file-by-name/content detector."""

from __future__ import annotations

from pathlib import Path

from repo_airlock.detectors.cred_files import CredentialFileDetector


class TestCredentialFileDetector:
    def setup_method(self) -> None:
        self.detector = CredentialFileDetector()

    def test_flags_dotenv(self, tmp_path: Path) -> None:
        f = tmp_path / ".env"
        f.write_text("SECRET=1")
        findings = self.detector.scan_path(tmp_path, ".env", f)
        assert len(findings) == 1

    def test_flags_dotenv_variant(self, tmp_path: Path) -> None:
        f = tmp_path / ".env.production"
        f.write_text("SECRET=1")
        findings = self.detector.scan_path(tmp_path, ".env.production", f)
        assert len(findings) == 1

    def test_flags_pem(self, tmp_path: Path) -> None:
        f = tmp_path / "server.pem"
        f.write_text("-----BEGIN CERTIFICATE-----")
        findings = self.detector.scan_path(tmp_path, "server.pem", f)
        assert len(findings) == 1

    def test_flags_id_rsa(self, tmp_path: Path) -> None:
        f = tmp_path / "id_rsa"
        f.write_text("fake key content")
        findings = self.detector.scan_path(tmp_path, "id_rsa", f)
        assert len(findings) == 1

    def test_flags_netrc(self, tmp_path: Path) -> None:
        f = tmp_path / ".netrc"
        f.write_text("machine example.com login me password x")
        findings = self.detector.scan_path(tmp_path, ".netrc", f)
        assert len(findings) == 1

    def test_flags_service_account_json_by_content(self, tmp_path: Path) -> None:
        f = tmp_path / "gcp-config.json"
        f.write_text('{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----"}')
        findings = self.detector.scan_path(tmp_path, "gcp-config.json", f)
        assert len(findings) == 1
        assert "service-account" in findings[0].detector_id

    def test_ignores_ordinary_json(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        f.write_text('{"name": "thing", "version": "1.0.0"}')
        findings = self.detector.scan_path(tmp_path, "package.json", f)
        assert findings == []

    def test_ignores_ordinary_python_file(self, tmp_path: Path) -> None:
        f = tmp_path / "main.py"
        f.write_text("print('hello')")
        findings = self.detector.scan_path(tmp_path, "main.py", f)
        assert findings == []
