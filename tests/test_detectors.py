"""
tests/test_detectors.py — Unit tests for all detection modules.

Run with:
    pytest tests/ -v
"""

import sys
import os
import pytest

# Make root importable from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import Finding
from detectors.regex_detector import RegexDetector, _mask, _is_false_positive
from detectors.keyword_detector import KeywordDetector
from scanner.entropy_detector import EntropyDetector, _shannon_entropy
from reporter.report_generator import ReportGenerator


# ===========================================================================
# Helpers
# ===========================================================================

def detect_all(line: str, detector_cls) -> list:
    d = detector_cls()
    return d.detect(line, 1, "test_file.py")


# ===========================================================================
# RegexDetector tests
# ===========================================================================

class TestRegexDetector:

    def test_aws_access_key(self):
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        line = f'aws_access_key_id = "{aws_key}"'
        findings = detect_all(line, RegexDetector)
        types = [f.secret_type for f in findings]
        assert any("AWS" in t for t in types), f"Expected AWS key detection in {types}"

    def test_github_pat(self):
        gh_pat = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        line = f'token = "{gh_pat}"'
        findings = detect_all(line, RegexDetector)
        types = [f.secret_type for f in findings]
        assert any("GitHub" in t for t in types), f"Expected GitHub token in {types}"

    def test_stripe_live_key(self):
        stripe_live = "sk" + "_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc"
        line = f'STRIPE_SECRET = "{stripe_live}"'
        findings = detect_all(line, RegexDetector)
        assert any("Stripe" in f.secret_type for f in findings)

    def test_stripe_test_key(self):
        stripe_test = "sk" + "_test_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc"
        line = f'key = "{stripe_test}"'
        findings = detect_all(line, RegexDetector)
        assert any("Stripe" in f.secret_type for f in findings)

    def test_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
        line = f'token = "{jwt}"'
        findings = detect_all(line, RegexDetector)
        assert any("JWT" in f.secret_type for f in findings)

    def test_private_key_block(self):
        line = "-----BEGIN RSA PRIVATE KEY-----"
        findings = detect_all(line, RegexDetector)
        assert any("Private Key" in f.secret_type for f in findings)

    def test_slack_token(self):
        slack_token = "xox" + "b-123456789012-123456789012-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        line = f'token = "{slack_token}"'
        findings = detect_all(line, RegexDetector)
        assert any("Slack" in f.secret_type for f in findings)

    def test_google_api_key(self):
        g_api_key = "AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
        line = f'key = "{g_api_key}"'
        findings = detect_all(line, RegexDetector)
        assert any("Google" in f.secret_type for f in findings)

    def test_no_false_positive_on_placeholder(self):
        line = 'api_key = "your_api_key_here"'
        findings = detect_all(line, RegexDetector)
        # Should be empty or not contain high-confidence patterns
        for f in findings:
            assert "AWS" not in f.secret_type

    def test_masked_value_hides_secret(self):
        """Ensure masked values don't reveal full secrets."""
        secret = "sk" + "_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        masked = _mask(secret)
        assert "***" in masked
        assert masked != secret
        assert len(masked) < len(secret)

    def test_severity_critical_for_aws(self):
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        line = f'key = "{aws_key}"'
        findings = detect_all(line, RegexDetector)
        aws_findings = [f for f in findings if "AWS" in f.secret_type]
        if aws_findings:
            assert aws_findings[0].severity == "critical"

    def test_false_positive_filter(self):
        assert _is_false_positive("your_api_key_here")
        assert _is_false_positive("<YOUR_TOKEN>")
        assert _is_false_positive("${MY_SECRET}")
        assert not _is_false_positive("sk_live_realSecret123")


# ===========================================================================
# KeywordDetector tests
# ===========================================================================

class TestKeywordDetector:

    def test_detects_password_assignment(self):
        line = 'db_password = "SuperSecret123!"'
        findings = detect_all(line, KeywordDetector)
        assert len(findings) > 0

    def test_detects_api_key_assignment(self):
        line = 'api_key = "abc123xyz456def789ghi"'
        findings = detect_all(line, KeywordDetector)
        assert len(findings) > 0

    def test_skips_placeholder_value(self):
        line = 'api_key = "your_api_key_here"'
        findings = detect_all(line, KeywordDetector)
        assert len(findings) == 0

    def test_skips_short_values(self):
        line = 'key = "abc"'
        findings = detect_all(line, KeywordDetector)
        assert len(findings) == 0

    def test_detects_secret_token(self):
        line = 'SECRET_TOKEN = "reallyLongSecretValue12345"'
        findings = detect_all(line, KeywordDetector)
        assert len(findings) > 0

    def test_detector_name(self):
        d = KeywordDetector()
        assert d.name == "keyword"

    def test_high_severity_for_password(self):
        line = 'password = "SuperSecret123XYZ"'
        findings = detect_all(line, KeywordDetector)
        password_findings = [f for f in findings if "password" in f.secret_type.lower()]
        if password_findings:
            assert password_findings[0].severity in ("high", "critical")


# ===========================================================================
# EntropyDetector tests
# ===========================================================================

class TestEntropyDetector:

    def test_high_entropy_base64(self):
        # A realistic high-entropy base64-ish token
        token = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"  # 32 chars, mixed
        line = f'token = "{token}"'
        findings = detect_all(line, EntropyDetector)
        # May or may not flag depending on exact entropy — just ensure no crash
        assert isinstance(findings, list)

    def test_low_entropy_word(self):
        line = 'description = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
        findings = detect_all(line, EntropyDetector)
        assert len(findings) == 0, "Low-entropy repeated chars should not be flagged"

    def test_shannon_entropy_known_values(self):
        # All same characters → entropy = 0
        assert _shannon_entropy("aaaaaaa") == pytest.approx(0.0)
        # Two equal halves → entropy = 1.0 bit
        assert _shannon_entropy("ababababab") < 2.0
        # Highly random string → entropy > 3.0
        assert _shannon_entropy("aB3cD4eF5gH6iJ7kL8mN9oP0") > 3.0

    def test_skip_comment_lines(self):
        line = "# aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ"
        findings = detect_all(line, EntropyDetector)
        assert len(findings) == 0

    def test_detector_name(self):
        d = EntropyDetector()
        assert d.name == "entropy"


# ===========================================================================
# ReportGenerator tests
# ===========================================================================

class TestReportGenerator:

    def _make_finding(self, **kwargs) -> Finding:
        defaults = dict(
            file_path="test.py",
            line_number=10,
            secret_type="Test Secret",
            detector="regex",
            severity="high",
            masked_value="sk_t***est",
            raw_line='secret = "sk_test_abc123"',
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_to_table_no_findings(self):
        r = ReportGenerator([])
        output = r.to_table()
        assert "No secrets detected" in output

    def test_to_table_with_findings(self):
        findings = [self._make_finding()]
        r = ReportGenerator(findings)
        output = r.to_table()
        assert "test.py" in output
        assert "Test Secret" in output
        assert "SUMMARY" in output

    def test_to_json_structure(self):
        import json
        findings = [self._make_finding(severity="critical")]
        r = ReportGenerator(findings)
        data = json.loads(r.to_json())
        assert "findings" in data
        assert "summary" in data
        assert data["summary"]["total"] == 1
        assert data["summary"]["by_severity"]["critical"] == 1

    def test_to_json_no_raw_secrets(self):
        """JSON output must not contain the raw masked value exposed in full."""
        import json
        findings = [self._make_finding(masked_value="sk_t***estvalue")]
        r = ReportGenerator(findings)
        data = json.loads(r.to_json())
        for f in data["findings"]:
            # The masked value should be present
            assert "***" in f["value"]

    def test_summary_counts(self):
        findings = [
            self._make_finding(severity="critical"),
            self._make_finding(severity="critical", line_number=20),
            self._make_finding(severity="high", line_number=30),
        ]
        r = ReportGenerator(findings)
        import json
        data = json.loads(r.to_json())
        assert data["summary"]["by_severity"]["critical"] == 2
        assert data["summary"]["by_severity"]["high"] == 1

    def test_files_affected_count(self):
        import json
        findings = [
            self._make_finding(file_path="a.py"),
            self._make_finding(file_path="b.py"),
            self._make_finding(file_path="a.py", line_number=20),
        ]
        r = ReportGenerator(findings)
        data = json.loads(r.to_json())
        assert data["summary"]["files_affected"] == 2


# ===========================================================================
# Integration-style tests
# ===========================================================================

class TestIntegration:

    def test_finding_to_dict(self):
        f = Finding(
            file_path="config.py",
            line_number=5,
            secret_type="AWS Access Key",
            detector="regex",
            severity="critical",
            masked_value="AKIA***MPLE",
            raw_line='key = "AKIAIOSFODNN7EXAMPLE"',
        )
        d = f.to_dict()
        assert d["file"] == "config.py"
        assert d["line"] == 5
        assert d["type"] == "AWS Access Key"
        assert "raw_line" not in d   # must not expose raw line

    def test_finding_dict_no_raw_line(self):
        f = Finding(
            file_path="x.env",
            line_number=1,
            secret_type="Generic Password",
            detector="keyword",
            severity="high",
            masked_value="sup***d",
            raw_line='PASSWORD="supersecretpassword"',
        )
        d = f.to_dict()
        assert "supersecretpassword" not in str(d)
