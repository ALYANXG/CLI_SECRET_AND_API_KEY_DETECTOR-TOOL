"""
models.py — Shared data structures used across all modules.
"""

from dataclasses import dataclass, field
from typing import Optional


# Severity levels ordered from least to most severe
SEVERITY_LEVELS = ("low", "medium", "high", "critical")


@dataclass
class Finding:
    """
    Represents a single detected secret or sensitive value.

    Attributes:
        file_path   : Relative or absolute path to the file containing the secret.
        line_number : 1-based line number where the match was found.
        secret_type : Human-readable label, e.g. "AWS Access Key", "JWT Token".
        detector    : Which detector produced this finding: 'regex', 'entropy', 'keyword'.
        severity    : One of 'low', 'medium', 'high', 'critical'.
        masked_value: The matched value with the middle portion replaced by '***'.
        raw_line    : The full source line (used for context; never printed in full).
        context     : Optional surrounding lines for debugging.
    """

    file_path: str
    line_number: int
    secret_type: str
    detector: str
    severity: str
    masked_value: str
    raw_line: str = field(repr=False)
    context: Optional[str] = field(default=None, repr=False)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        """Serialise to a plain dict (JSON-safe, no raw secrets)."""
        return {
            "file": self.file_path,
            "line": self.line_number,
            "type": self.secret_type,
            "detector": self.detector,
            "severity": self.severity,
            "value": self.masked_value,
        }
