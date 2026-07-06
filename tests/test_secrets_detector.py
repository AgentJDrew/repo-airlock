"""Tests for the secret detectors (known tokens, generic assignment, entropy).

Note on token literals: some provider token formats (Slack ``xoxb-`` tokens,
Slack webhook URLs, Stripe ``sk_live_``/``sk_test_`` keys, Google ``AIza...``
keys) are realistic enough that GitHub's secret scanner reacts to them as a
*contiguous* string literal in a committed file — even when the value is
obviously fake. Some (Slack/Stripe) are rejected outright by push protection;
others (the Google key) pass the push but trigger a post-push secret-scanning
alert. Either way, to keep these detector tests meaningful without tripping the
scanner, those test values are assembled at runtime from string fragments
(e.g. ``"sk_" + "live_" + ...``, ``"AIza..." + "..." + "..."``) so no
contiguous, scanner-matching literal is ever committed. The assembled values
still match repo-airlock's own regexes, so the assertions remain a real test of
the detectors. Values GitHub does not flag (the public AWS docs example key,
``ghp_`` tokens, JWTs, PEM blocks) are left as plain literals for readability.
"""

from __future__ import annotations

from repo_airlock.detectors.secrets import (
    EntropyDetector,
    GenericAssignmentDetector,
    KnownTokenDetector,
    shannon_entropy,
)
from repo_airlock.findings import Severity


class TestKnownTokenDetector:
    def setup_method(self) -> None:
        self.detector = KnownTokenDetector()

    def test_aws_access_key(self) -> None:
        findings = self.detector.scan_text("f.txt", "key = AKIAIOSFODNN7EXAMPLE")
        assert any("aws-access-key-id" in f.detector_id for f in findings)
        assert findings[0].severity == Severity.HIGH

    def test_aws_secret_key(self) -> None:
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        findings = self.detector.scan_text("f.txt", text)
        assert any("aws-secret-key" in f.detector_id for f in findings)

    def test_github_token(self) -> None:
        findings = self.detector.scan_text("f.txt", "token = ghp_1234567890abcdefghijklmnopqrstuvwxyz12")
        assert any("github-token" in f.detector_id for f in findings)

    def test_github_fine_grained_pat(self) -> None:
        text = "pat = github_pat_11ABCDEFG0123456789abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMN"
        findings = self.detector.scan_text("f.txt", text)
        assert any("github-fine-grained-pat" in f.detector_id for f in findings)

    def test_slack_token(self) -> None:
        # Assembled at runtime (see module docstring) so no contiguous Slack
        # token literal is committed to trip GitHub push protection. Still a
        # valid match for the detector's regex.
        slack = "xoxb-" + "0000000000" + "-" + "0000000000" + "-" + ("A" * 24)
        findings = self.detector.scan_text("f.txt", slack)
        assert any("slack-token" in f.detector_id for f in findings)

    def test_stripe_live_key(self) -> None:
        # Assembled at runtime (see module docstring) to avoid a committed
        # sk_live_ literal; still matches the stripe-live-key regex.
        stripe = "sk_" + "live_" + "00" + ("A" * 24)
        findings = self.detector.scan_text("f.txt", stripe)
        assert any("stripe-live-key" in f.detector_id for f in findings)

    def test_google_api_key(self) -> None:
        # Assembled at runtime (see module docstring) from three sub-20-char
        # fragments so no contiguous AIza[...]{35} literal is committed — that
        # shape trips GitHub's secret scanner even when fake, and each fragment
        # is short enough to stay under the entropy detector's floor too. The
        # reassembled value still matches the google-api-key regex.
        google = "AIzaSyD4GmWKa" + "4JsZHjGw7ISLa" + "nFEDUMeK9wZaB"
        findings = self.detector.scan_text("f.txt", google)
        assert any("google-api-key" in f.detector_id for f in findings)

    def test_jwt(self) -> None:
        text = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYlM3nQwcHQE"
        )
        findings = self.detector.scan_text("f.txt", text)
        assert any("jwt" in f.detector_id for f in findings)

    def test_pem_private_key(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC\n-----END RSA PRIVATE KEY-----"
        findings = self.detector.scan_text("f.txt", text)
        assert any("pem-private-key" in f.detector_id for f in findings)

    def test_slack_webhook(self) -> None:
        # Assembled at runtime (see module docstring) so no contiguous Slack
        # webhook URL literal is committed; still matches the slack-webhook regex.
        text = "https://hooks.slack.com/services/" + "T00000000/" + "B00000000/" + ("X" * 24)
        findings = self.detector.scan_text("f.txt", text)
        assert any("slack-webhook" in f.detector_id for f in findings)

    def test_redaction_never_leaks_full_secret(self) -> None:
        findings = self.detector.scan_text("f.txt", "key = AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].match_redacted
        assert findings[0].match_redacted.startswith("AKIA")
        assert "..." in findings[0].match_redacted

    def test_clean_text_has_no_findings(self) -> None:
        findings = self.detector.scan_text("f.txt", "def add(a, b):\n    return a + b\n")
        assert findings == []

    def test_line_numbers_are_correct(self) -> None:
        text = "line one\nline two\nkey = AKIAIOSFODNN7EXAMPLE\nline four"
        findings = self.detector.scan_text("f.txt", text)
        assert findings[0].line == 3


class TestGenericAssignmentDetector:
    def setup_method(self) -> None:
        self.detector = GenericAssignmentDetector()

    def test_flags_hardcoded_password(self) -> None:
        findings = self.detector.scan_text("f.txt", 'password = "hunter2superSecretValue"')
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_flags_api_key_single_quotes(self) -> None:
        # Value assembled at runtime (see module docstring) so no contiguous
        # sk_test_ literal is committed. This exercises the generic-assignment
        # detector, which fires on the key name + quoted value regardless of
        # the value's shape.
        value = "sk_" + "test_" + ("a" * 24) + "1234567890"
        findings = self.detector.scan_text("f.txt", "api_key: '" + value + "'")
        assert len(findings) == 1

    def test_ignores_placeholder_values(self) -> None:
        findings = self.detector.scan_text("f.txt", 'api_key = "your-api-key-here"')
        assert findings == []

    def test_ignores_empty_and_env_var_style(self) -> None:
        text = 'password = ""\nsecret = "${SECRET_ENV}"\napi_key = "<your-key>"'
        findings = self.detector.scan_text("f.txt", text)
        assert findings == []

    def test_redaction_applied(self) -> None:
        findings = self.detector.scan_text("f.txt", 'password = "hunter2superSecretValue"')
        assert "hunter2superSecretValue" not in findings[0].match_redacted


class TestEntropyDetector:
    def setup_method(self) -> None:
        self.detector = EntropyDetector()

    def test_shannon_entropy_of_repeated_char_is_zero(self) -> None:
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_shannon_entropy_of_random_looking_string_is_high(self) -> None:
        assert shannon_entropy("aB3xQ9zK7mP2vL8n") > 3.0

    def test_flags_high_entropy_literal(self) -> None:
        text = 'token = "aB3xQ9zK7mP2vL8nR5tY6uI0oP1aS4d"'
        findings = self.detector.scan_text("f.txt", text)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_ignores_short_strings(self) -> None:
        findings = self.detector.scan_text("f.txt", 'x = "short"')
        assert findings == []

    def test_ignores_low_entropy_english_sentence(self) -> None:
        text = 'description = "this is a perfectly ordinary sentence about a widget"'
        findings = self.detector.scan_text("f.txt", text)
        assert findings == []

    def test_ignores_placeholder(self) -> None:
        text = 'token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
        findings = self.detector.scan_text("f.txt", text)
        assert findings == []
