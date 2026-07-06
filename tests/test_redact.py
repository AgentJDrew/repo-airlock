"""Tests for redaction helper — the safety net that prevents leaking secrets in reports."""

from __future__ import annotations

from repo_airlock.redact import redact


class TestRedact:
    def test_keeps_first_and_last_four_chars(self) -> None:
        assert redact("AKIAIOSFODNN7EXAMPLE") == "AKIA...MPLE"

    def test_full_value_never_appears_in_output(self) -> None:
        secret = "supersecretvalue1234567890"
        result = redact(secret)
        assert secret not in result

    def test_short_value_fully_masked(self) -> None:
        result = redact("short")
        assert result == "*****"
        assert "short" not in result

    def test_empty_string(self) -> None:
        assert redact("") == ""

    def test_strips_whitespace_before_redacting(self) -> None:
        assert redact("  AKIAIOSFODNN7EXAMPLE  ") == "AKIA...MPLE"
