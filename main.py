#!/usr/bin/env python3
"""
Secret and API Key Detector
============================
A production-ready CLI tool for scanning files and directories
for hardcoded secrets, API keys, tokens, and passwords.

Usage:
    secret-detector scan <path> [options]
"""

import sys
import argparse
from pathlib import Path
from scanner.file_scanner import FileScanner
from reporter.report_generator import ReportGenerator


def _configure_stdout_for_unicode() -> None:
    """
    Best-effort UTF-8 stdout/stderr setup for Windows terminals.
    Prevents emoji/report rendering crashes on legacy code pages.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                # Keep default stream settings if reconfigure is unavailable.
                pass


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="secret-detector",
        description="🔍 Scan files and directories for hardcoded secrets and API keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secret-detector scan ./my-project
  secret-detector scan ./config.env --json
  secret-detector scan . --severity high --exclude node_modules dist
  secret-detector scan . --no-entropy
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan subcommand ---
    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory for secrets")
    scan_parser.add_argument(
        "path",
        type=str,
        help="File or directory path to scan",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output results in JSON format",
    )
    scan_parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Only show findings at or above this severity level",
    )
    scan_parser.add_argument(
        "--no-entropy",
        action="store_true",
        dest="no_entropy",
        help="Disable entropy-based detection",
    )
    scan_parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        metavar="DIR",
        help="Directory or file names to exclude (e.g. node_modules .git)",
    )
    scan_parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="Write results to a file instead of stdout",
    )

    return parser


def main() -> int:
    """Entry point. Returns exit code (0 = clean, 1 = secrets found, 2 = error)."""
    _configure_stdout_for_unicode()
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 2

    if args.command == "scan":
        target = Path(args.path)

        if not target.exists():
            print(f"[ERROR] Path does not exist: {target}", file=sys.stderr)
            return 2

        # Run the scanner
        scanner = FileScanner(
            use_entropy=not args.no_entropy,
            exclude_patterns=args.exclude,
        )
        findings = scanner.scan(target)

        # Apply severity filter
        if args.severity:
            severity_order = ["low", "medium", "high", "critical"]
            min_idx = severity_order.index(args.severity)
            findings = [
                f for f in findings
                if severity_order.index(f.severity) >= min_idx
            ]

        # Generate report
        reporter = ReportGenerator(findings)

        if args.output_json:
            output = reporter.to_json()
        else:
            output = reporter.to_table()

        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Results written to: {args.output}")
        else:
            print(output)

        # Exit 1 if any secrets found (useful for CI pipelines)
        return 1 if findings else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
