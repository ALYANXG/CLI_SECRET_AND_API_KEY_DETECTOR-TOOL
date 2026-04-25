"""
keyword_detector.py — Keyword-based detection for suspicious variable assignments.

Looks for common naming conventions that suggest a variable holds a secret
(e.g. `api_key = "..."`, `SECRET_TOKEN: "..."`).  This complements the regex
detector by catching patterns where the *value* format is unknown but the
*name* is a dead giveaway.
"""

import re
from typing import List

from models import Finding


# ---------------------------------------------------------------------------
# Suspicious keyword groups with associated severity
# ---------------------------------------------------------------------------
_KEYWORD_RULES: List[tuple] = [
    # (keywords, severity)
    (["private_key", "privatekey", "rsa_key", "ecdsa_key", "dsa_key"], "critical"),
    (["secret_key", "secretkey", "app_secret", "client_secret"], "critical"),
    (["api_secret", "apisecret"], "critical"),
    (["password", "passwd", "pass", "pwd"], "high"),
    (["api_key", "apikey", "access_key", "accesskey"], "high"),
    (["auth_token", "authtoken", "access_token", "accesstoken"], "high"),
    (["secret_token", "secrettoken", "signing_secret"], "high"),
    (["bearer_token", "bearertoken"], "high"),
    (["db_password", "database_password", "db_pass", "db_pwd"], "critical"),
    (["smtp_password", "smtp_pass", "mail_password"], "high"),
    (["webhook_secret", "webhook_token", "hook_secret"], "high"),
    (["encryption_key", "encrypt_key", "aes_key", "cipher_key"], "critical"),
    (["jwt_secret", "jwt_key", "token_secret"], "high"),
    (["oauth_secret", "oauth_token", "oauth_key"], "high"),
    (["credential", "credentials"], "medium"),
    (["token", "secret", "key"], "low"),  # generic — lower severity
]

# Flatten to (keyword, severity) pairs for fast lookup
_KEYWORD_SEVERITY: dict = {}
for keywords, sev in _KEYWORD_RULES:
    for kw in keywords:
        _KEYWORD_SEVERITY[kw.lower()] = sev

# Match: <word_chars>=<quoted_value> or <word_chars>:<quoted_value>
# The value must be quoted and non-trivially short (≥ 6 chars excluding quotes)
_ASSIGNMENT_RE = re.compile(
    r"""
    (?:^|[,\s\{])              # start of line / whitespace / dict context
    ([A-Za-z][A-Za-z0-9_\-]*)  # variable name  (group 1)
    \s*[:=]\s*                 # assignment operator
    (?:f?[\"'`]|\"\"\"|\'\'\') # opening quote (supports f-strings, triple quotes)
    ([^\"'`\n]{6,200})         # value — at least 6 chars (group 2)
    [\"'`]                     # closing quote
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Placeholder values — skip these
_PLACEHOLDER_RE = re.compile(
    r"^(?:your[-_]?|<[^>]+>|\$\{[^}]+\}|%[A-Z_]+%|#{[^}]+}|"
    r"example|test|dummy|placeholder|TODO|CHANGEME|FIXME|xxx+)",
    re.IGNORECASE,
)

# Minimum value length to avoid catching "password = 'abc'"
_MIN_VALUE_LEN = 6


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    visible = max(3, len(value) // 6)
    return value[:visible] + "***" + value[-visible:]


class KeywordDetector:
    """
    Identifies suspicious variable assignments based on keyword matching.

    Only matches lines where:
      1. A known suspicious keyword appears in the variable name.
      2. The assigned value is quoted and long enough to be a real secret.
      3. The value doesn't look like a documentation placeholder.
    """

    name = "keyword"

    def detect(self, line: str, lineno: int, filepath: str) -> List[Finding]:
        findings: List[Finding] = []

        for match in _ASSIGNMENT_RE.finditer(line):
            var_name = match.group(1).lower().replace("-", "_")
            value = match.group(2).strip()

            # Skip placeholders and very short values
            if len(value) < _MIN_VALUE_LEN or _PLACEHOLDER_RE.match(value):
                continue

            # Check if the variable name contains a suspicious keyword
            severity = self._classify(var_name)
            if severity is None:
                continue

            findings.append(Finding(
                file_path=filepath,
                line_number=lineno,
                secret_type=f"Keyword Match ({match.group(1)})",
                detector=self.name,
                severity=severity,
                masked_value=_mask(value),
                raw_line=line,
            ))

        return findings

    def _classify(self, var_name: str) -> str | None:
        """Return the severity for *var_name*, or None if not suspicious."""
        # Exact match first
        if var_name in _KEYWORD_SEVERITY:
            return _KEYWORD_SEVERITY[var_name]
        # Substring match (e.g. "my_api_key_prod" contains "api_key")
        for keyword, severity in _KEYWORD_SEVERITY.items():
            if keyword in var_name:
                return severity
        return None
