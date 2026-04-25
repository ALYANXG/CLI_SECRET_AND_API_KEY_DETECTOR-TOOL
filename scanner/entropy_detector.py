"""
entropy_detector.py — Shannon-entropy-based secret detection.

High-entropy strings (Base64, hex, random alphanumeric) are strong indicators
of embedded secrets even when no known pattern matches.

Algorithm
---------
1. Tokenise the line into candidate strings using a broad regex.
2. Compute the Shannon entropy of each candidate.
3. Flag candidates that exceed the configurable threshold AND meet a
   minimum length requirement (to reduce false positives on short random words).
"""

import re
import math
from typing import List, Generator

from models import Finding


# ---------------------------------------------------------------------------
# Tunable thresholds
# ---------------------------------------------------------------------------
# Entropy is measured in bits per character (log2 of symbol diversity).
# Random Base64 is ~6 bits/char; random hex ~4 bits/char; English prose ~4.
ENTROPY_THRESHOLD_BASE64 = 4.5   # catches most Base64 secrets
ENTROPY_THRESHOLD_HEX    = 3.5   # catches long hex strings

# Only flag tokens at or above this length — avoids false hits on short words
MIN_TOKEN_LENGTH = 20

# Alphabets used to classify token type
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
HEX_CHARS    = set("0123456789abcdefABCDEF")

# Pattern to extract candidate tokens from a line
# Skips common non-secret patterns (file paths, URLs, etc.)
_TOKEN_RE = re.compile(r"""
    (?<![/\\.])              # not preceded by path separators
    [A-Za-z0-9+/=_\-]{20,}  # at least 20 chars of base64-ish alphabet
    (?![/\\])                # not followed by path separators
""", re.VERBOSE)

# Lines that almost certainly aren't secrets
_SKIP_LINE_RE = re.compile(
    r"^\s*#|^\s*//|^\s*/\*|import |from |require\(|console\.|print\(|log\."
)


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits/char) of string *s*."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _mask(value: str) -> str:
    """Mask the middle portion of a string."""
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]


class EntropyDetector:
    """
    Detects high-entropy strings that are likely to be secrets.

    This detector produces lower-severity findings than the regex detector
    because entropy alone doesn't confirm the *type* of secret — it is a
    signal, not a pattern match.
    """

    name = "entropy"

    def detect(self, line: str, lineno: int, filepath: str) -> List[Finding]:
        """Return findings for any high-entropy tokens found on *line*."""
        # Skip comment lines and common non-secret patterns
        if _SKIP_LINE_RE.match(line):
            return []

        findings: List[Finding] = []
        for token in _TOKEN_RE.findall(line):
            finding = self._evaluate_token(token, line, lineno, filepath)
            if finding:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------ #

    def _evaluate_token(
        self, token: str, line: str, lineno: int, filepath: str
    ) -> Finding | None:
        """Return a Finding if the token exceeds entropy thresholds."""
        chars = set(token)

        is_hex    = chars.issubset(HEX_CHARS) and len(token) >= 32
        is_base64 = chars.issubset(BASE64_CHARS) and len(token) >= MIN_TOKEN_LENGTH

        if not (is_hex or is_base64):
            return None

        entropy = _shannon_entropy(token)

        if is_hex and entropy >= ENTROPY_THRESHOLD_HEX:
            secret_type = "High-Entropy Hex String"
            severity = "medium"
        elif is_base64 and entropy >= ENTROPY_THRESHOLD_BASE64:
            secret_type = "High-Entropy Base64 String"
            severity = "medium"
        else:
            return None

        return Finding(
            file_path=filepath,
            line_number=lineno,
            secret_type=secret_type,
            detector=self.name,
            severity=severity,
            masked_value=_mask(token),
            raw_line=line,
            context=f"entropy={entropy:.2f} bits/char, length={len(token)}",
        )
