"""
report_generator.py — Format and render scan results.

Provides two output modes:
  - Table   : Colour-coded, human-readable terminal output.
  - JSON    : Machine-readable structured output for CI integration.
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any

from models import Finding


# ---------------------------------------------------------------------------
# ANSI colour codes (gracefully degrade on non-colour terminals)
# ---------------------------------------------------------------------------
try:
    import sys
    _COLOUR = sys.stdout.isatty()
except Exception:
    _COLOUR = False


class Colours:
    RESET  = "\033[0m"  if _COLOUR else ""
    BOLD   = "\033[1m"  if _COLOUR else ""
    RED    = "\033[91m" if _COLOUR else ""
    YELLOW = "\033[93m" if _COLOUR else ""
    CYAN   = "\033[96m" if _COLOUR else ""
    GREEN  = "\033[92m" if _COLOUR else ""
    DIM    = "\033[2m"  if _COLOUR else ""
    ORANGE = "\033[33m" if _COLOUR else ""


_SEVERITY_COLOUR = {
    "critical": Colours.RED,
    "high":     Colours.ORANGE,
    "medium":   Colours.YELLOW,
    "low":      Colours.DIM,
}

_SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "⚪",
}


def _col(text: str, colour: str) -> str:
    return f"{colour}{text}{Colours.RESET}"


class ReportGenerator:
    """
    Generates formatted reports from a list of Finding objects.

    Parameters
    ----------
    findings : List[Finding]
        The raw findings produced by the scanner.
    """

    def __init__(self, findings: List[Finding]) -> None:
        self._findings = findings

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def to_table(self) -> str:
        """Return a human-readable, colour-coded table string."""
        lines: List[str] = []
        lines.append("")
        lines.append(_col("  ╔══════════════════════════════════════════════╗", Colours.BOLD))
        lines.append(_col("  ║       🔍  Secret & API Key Detector          ║", Colours.BOLD))
        lines.append(_col("  ╚══════════════════════════════════════════════╝", Colours.BOLD))
        lines.append("")

        if not self._findings:
            lines.append(_col("  ✅  No secrets detected.", Colours.GREEN))
            lines.append("")
            return "\n".join(lines)

        # Group findings by file
        by_file: Dict[str, List[Finding]] = {}
        for f in self._findings:
            by_file.setdefault(f.file_path, []).append(f)

        summary = self._build_summary()

        for filepath, file_findings in by_file.items():
            lines.append(_col(f"  📄 {filepath}", Colours.BOLD + Colours.CYAN))
            lines.append(_col(f"  {'─' * 70}", Colours.DIM))

            # Column widths
            for finding in file_findings:
                sev_col = _SEVERITY_COLOUR.get(finding.severity, "")
                icon    = _SEVERITY_ICON.get(finding.severity, "•")
                sev_label = _col(
                    f"{icon} {finding.severity.upper():<8}", sev_col
                )
                line_ref  = _col(f"L{finding.line_number:<6}", Colours.DIM)
                det_label = _col(f"[{finding.detector}]", Colours.DIM)
                type_label = _col(finding.secret_type, Colours.BOLD)
                value_label = _col(finding.masked_value, Colours.YELLOW)

                lines.append(
                    f"    {sev_label}  {line_ref}  {type_label}"
                )
                lines.append(
                    f"              {det_label} Value: {value_label}"
                )
                if finding.context:
                    lines.append(
                        _col(f"              Context: {finding.context}", Colours.DIM)
                    )
                lines.append("")

        # Summary block
        lines.append(_col(f"  {'═' * 70}", Colours.DIM))
        lines.append(_col("  📊 SUMMARY", Colours.BOLD))
        lines.append(_col(f"  {'─' * 30}", Colours.DIM))
        lines.append(f"  Total findings : {_col(str(summary['total']), Colours.BOLD)}")
        lines.append(f"  Files affected : {_col(str(summary['files_affected']), Colours.BOLD)}")
        lines.append("")
        lines.append("  By severity:")
        for sev in ("critical", "high", "medium", "low"):
            count = summary["by_severity"].get(sev, 0)
            if count:
                c = _SEVERITY_COLOUR.get(sev, "")
                sev_upper = f"{sev.upper():<10}"
                lines.append(
                    f"    {_SEVERITY_ICON[sev]}  {_col(sev_upper, c)}  {count}"
                )
        lines.append("")
        lines.append("  By detector:")
        for det, count in summary["by_detector"].items():
            lines.append(f"    • {det:<12} {count}")
        lines.append("")

        if summary["by_severity"].get("critical", 0) > 0:
            lines.append(_col(
                "  ⚠️  CRITICAL findings detected — rotate affected credentials immediately!",
                Colours.RED + Colours.BOLD,
            ))
            lines.append("")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Return a JSON string suitable for CI pipelines."""
        summary = self._build_summary()
        output: Dict[str, Any] = {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "findings": [f.to_dict() for f in self._findings],
        }
        return json.dumps(output, indent=2)

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    def _build_summary(self) -> Dict[str, Any]:
        by_severity: Dict[str, int] = {}
        by_detector: Dict[str, int] = {}
        files: set = set()

        for f in self._findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_detector[f.detector] = by_detector.get(f.detector, 0) + 1
            files.add(f.file_path)

        return {
            "total": len(self._findings),
            "files_affected": len(files),
            "by_severity": by_severity,
            "by_detector": by_detector,
        }
