"""
regex_detector.py — Pattern-based detection for well-known secret formats.

Each entry in PATTERNS describes:
  - pattern : compiled regex that must produce a match group(1) containing the secret value
  - name    : human-readable type label
  - severity: 'low' | 'medium' | 'high' | 'critical'

Design notes
------------
* All patterns require at least one capture group — group(1) is the secret value.
* Patterns are anchored with negative look-behinds/aheads where possible to
  reduce false positives (e.g. avoid matching example values in docs).
* We deliberately do NOT log the full secret; only a masked version is stored.
"""

import re
from typing import List, NamedTuple

from models import Finding


class SecretPattern(NamedTuple):
    pattern: re.Pattern
    name: str
    severity: str


def _p(regex: str, flags: int = 0) -> re.Pattern:
    return re.compile(regex, flags)


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------
PATTERNS: List[SecretPattern] = [

    # ── Cloud Provider Credentials ─────────────────────────────────────── #
    SecretPattern(
        _p(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        "AWS Access Key ID", "critical",
    ),
    SecretPattern(
        _p(r"aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[=:\"'`]\s*([A-Za-z0-9/+]{40})", re.IGNORECASE),
        "AWS Secret Access Key", "critical",
    ),
    SecretPattern(
        _p(r"(?:AIza)([0-9A-Za-z_\-]{35})"),
        "Google API Key", "critical",
    ),
    SecretPattern(
        _p(r"ya29\.([0-9A-Za-z_\-]{100,})"),
        "Google OAuth Token", "critical",
    ),
    SecretPattern(
        _p(r"(?:AZURE|azure)[_\-\.]?(?:CLIENT|client)[_\-\.]?(?:SECRET|secret)\s*[=:\"'`]\s*([A-Za-z0-9_\-~.]{32,})"),
        "Azure Client Secret", "critical",
    ),

    # ── Stripe ─────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(sk_live_[0-9a-zA-Z]{24,})"),
        "Stripe Live Secret Key", "critical",
    ),
    SecretPattern(
        _p(r"(rk_live_[0-9a-zA-Z]{24,})"),
        "Stripe Live Restricted Key", "critical",
    ),
    SecretPattern(
        _p(r"(sk_test_[0-9a-zA-Z]{24,})"),
        "Stripe Test Secret Key", "high",
    ),
    SecretPattern(
        _p(r"(pk_live_[0-9a-zA-Z]{24,})"),
        "Stripe Live Publishable Key", "medium",
    ),

    # ── GitHub ─────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(ghp_[A-Za-z0-9]{36})"),
        "GitHub Personal Access Token", "critical",
    ),
    SecretPattern(
        _p(r"(gho_[A-Za-z0-9]{36})"),
        "GitHub OAuth Token", "critical",
    ),
    SecretPattern(
        _p(r"(ghu_[A-Za-z0-9]{36})"),
        "GitHub User-to-Server Token", "critical",
    ),
    SecretPattern(
        _p(r"(ghs_[A-Za-z0-9]{36})"),
        "GitHub Server-to-Server Token", "critical",
    ),
    SecretPattern(
        _p(r"(ghr_[A-Za-z0-9]{36})"),
        "GitHub Refresh Token", "critical",
    ),

    # ── GitLab ─────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(glpat-[A-Za-z0-9_\-]{20})"),
        "GitLab Personal Access Token", "critical",
    ),

    # ── Slack ──────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9A-Za-z]{24,})"),
        "Slack Token", "critical",
    ),
    SecretPattern(
        _p(r"https://hooks\.slack\.com/services/(T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"),
        "Slack Webhook URL", "high",
    ),

    # ── Twilio ─────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(SK[0-9a-fA-F]{32})"),
        "Twilio API Key", "critical",
    ),
    SecretPattern(
        _p(r"AC[0-9a-fA-F]{32}"),
        "Twilio Account SID", "high",
    ),

    # ── SendGrid ───────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"),
        "SendGrid API Key", "critical",
    ),

    # ── JWT ────────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"),
        "JSON Web Token (JWT)", "high",
    ),

    # ── SSH Private Keys ───────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----)", re.IGNORECASE),
        "Private Key Block", "critical",
    ),

    # ── Database / Connection Strings ──────────────────────────────────── #
    SecretPattern(
        _p(r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis)://[^:]+:([^@\s]{6,})@", re.IGNORECASE),
        "Database Connection String (password)", "critical",
    ),
    SecretPattern(
        _p(r"(?:DB|DATABASE)[_\-\.]?(?:PASSWORD|PASS|PWD)\s*[=:\"'`]\s*([^\s\"'`]{6,})", re.IGNORECASE),
        "Database Password", "critical",
    ),

    # ── Generic / Misc ─────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(?:password|passwd|pwd)\s*[=:\"'`]+\s*([^\s\"'`]{8,})", re.IGNORECASE),
        "Hardcoded Password", "high",
    ),
    SecretPattern(
        _p(r"(?:secret[_\-\.]?key|secret[_\-\.]?token|app[_\-\.]?secret)\s*[=:\"'`]+\s*([^\s\"'`]{8,})", re.IGNORECASE),
        "Generic Secret Key/Token", "high",
    ),
    SecretPattern(
        _p(r"(?:api[_\-\.]?key|api[_\-\.]?token)\s*[=:\"'`]+\s*([A-Za-z0-9_\-\/+]{16,})", re.IGNORECASE),
        "Generic API Key", "high",
    ),
    SecretPattern(
        _p(r"(?:access[_\-\.]?token|auth[_\-\.]?token|bearer[_\-\.]?token)\s*[=:\"'`]+\s*([A-Za-z0-9_\-\.\/+]{20,})", re.IGNORECASE),
        "Generic Access/Auth Token", "high",
    ),
    SecretPattern(
        _p(r"(?:PRIVATE[_\-\.]?KEY|PRIVATE[_\-\.]?TOKEN)\s*[=:\"'`]+\s*([A-Za-z0-9_\-\/+]{16,})", re.IGNORECASE),
        "Private Key Variable", "critical",
    ),

    # ── npm / PyPI publish tokens ───────────────────────────────────────── #
    SecretPattern(
        _p(r"(npm_[A-Za-z0-9]{36})"),
        "npm Access Token", "critical",
    ),
    SecretPattern(
        _p(r"(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})"),
        "PyPI API Token", "critical",
    ),

    # ── HuggingFace ─────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(hf_[A-Za-z]{34})"),
        "HuggingFace API Token", "critical",
    ),

    # ── Anthropic ───────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(sk-ant-[A-Za-z0-9_\-]{90,})"),
        "Anthropic API Key", "critical",
    ),

    # ── OpenAI ──────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(sk-[A-Za-z0-9]{48})"),
        "OpenAI API Key", "critical",
    ),

    # ── Mailgun / Mailchimp ─────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(key-[0-9a-zA-Z]{32})"),
        "Mailgun API Key", "high",
    ),

    # ── Discord ─────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(discord(?:[_\-\.]?(?:bot[_\-\.]?)?token)\s*[=:\"'`]+\s*)([A-Za-z0-9_\-\.]{50,})", re.IGNORECASE),
        "Discord Bot Token", "critical",
    ),

    # ── Telegram ────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(\d{8,10}:[A-Za-z0-9_\-]{35})"),
        "Telegram Bot Token", "critical",
    ),

    # ── Heroku ──────────────────────────────────────────────────────────── #
    SecretPattern(
        _p(r"(?:heroku[_\-\.]?api[_\-\.]?key)\s*[=:\"'`]+\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.IGNORECASE),
        "Heroku API Key", "critical",
    ),

    # ── Generic UUID-style secrets ──────────────────────────────────────── #
    SecretPattern(
        _p(r"(?:secret|token|key|password|passwd)\s*[=:\"'`]+\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.IGNORECASE),
        "UUID Secret / Token", "medium",
    ),
]


# ---------------------------------------------------------------------------
# False-positive filters
# ---------------------------------------------------------------------------
# Values matching these patterns are almost certainly placeholder examples
FP_PATTERNS = [
    re.compile(r"^(your[-_]?|my[-_]?|<|{|\$\{|%%|example|test|dummy|placeholder|xxx+|0{8,}|1{8,})", re.IGNORECASE),
    re.compile(r"^(INSERT|REPLACE|YOUR|MY|PUT|ADD|ENTER)[_ -]", re.IGNORECASE),
    re.compile(r"^[*]+$"),
]


def _is_false_positive(value: str) -> bool:
    return any(p.search(value) for p in FP_PATTERNS)


def _mask(value: str) -> str:
    """Replace the middle of a secret with *** for safe display."""
    if len(value) <= 8:
        return "***"
    visible = max(4, len(value) // 6)
    return value[:visible] + "***" + value[-visible:]


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------

class RegexDetector:
    """
    Applies all compiled patterns to a single line of text.
    Returns zero or more Finding objects.
    """

    name = "regex"

    def detect(self, line: str, lineno: int, filepath: str) -> List[Finding]:
        """Match all patterns against *line* and return findings."""
        findings: List[Finding] = []

        # Skip blank lines and lines that are clearly comments/imports
        stripped = line.strip()
        if not stripped or stripped.startswith("#!"):
            return findings

        for sp in PATTERNS:
            match = sp.pattern.search(line)
            if not match:
                continue

            # Extract the secret value from the last capture group
            secret_value = match.group(match.lastindex or 0)
            if not secret_value:
                continue

            if _is_false_positive(secret_value):
                continue

            findings.append(Finding(
                file_path=filepath,
                line_number=lineno,
                secret_type=sp.name,
                detector=self.name,
                severity=sp.severity,
                masked_value=_mask(secret_value),
                raw_line=line,
            ))

        return findings
