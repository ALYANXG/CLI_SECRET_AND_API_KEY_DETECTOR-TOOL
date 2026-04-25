"""
file_scanner.py — Directory/file traversal and detection orchestration.

Responsibilities:
  - Walk the target path (file or directory).
  - Skip binary files and excluded directories.
  - Feed each text line to all active detectors.
  - Deduplicate and return a sorted list of Finding objects.
"""

import os
from pathlib import Path
from typing import List, Set

from models import Finding
from detectors.regex_detector import RegexDetector
from detectors.keyword_detector import KeywordDetector
from scanner.entropy_detector import EntropyDetector


# ---------------------------------------------------------------------------
# File-type allow-list
# ---------------------------------------------------------------------------
SUPPORTED_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".cfg", ".ini", ".conf", ".config",
    ".json", ".yaml", ".yml", ".toml",
    ".php", ".java", ".kt", ".rb", ".go",
    ".sh", ".bash", ".zsh", ".fish",
    ".html", ".htm", ".xml",
    ".tf", ".tfvars",          # Terraform
    ".properties",             # Java / Spring Boot
    ".gradle",
    ".dockerfile", "dockerfile",
    ".md", ".txt",
    ".cs", ".cpp", ".c", ".h",
    ".rs",                     # Rust
    ".swift",
    ".vue", ".svelte",
}

# ---------------------------------------------------------------------------
# Directories that are nearly always noise
# ---------------------------------------------------------------------------
DEFAULT_EXCLUDED: Set[str] = {
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache",
    "venv", ".venv", "env", ".env_dir",
    "dist", "build", "out", "target",
    ".idea", ".vscode",
    "coverage", ".coverage",
    "vendor",
}

# Maximum file size to read (5 MB) — avoids hanging on huge generated files
MAX_FILE_BYTES = 5 * 1024 * 1024


class FileScanner:
    """
    Orchestrates scanning of a file or directory tree.

    Parameters
    ----------
    use_entropy:
        When True the EntropyDetector is included in the detector pipeline.
    exclude_patterns:
        Additional directory/file names to skip on top of DEFAULT_EXCLUDED.
    """

    def __init__(
        self,
        use_entropy: bool = True,
        exclude_patterns: List[str] | None = None,
    ) -> None:
        self._excluded: Set[str] = DEFAULT_EXCLUDED.copy()
        if exclude_patterns:
            self._excluded.update(exclude_patterns)

        # Build detector pipeline
        self._detectors = [
            RegexDetector(),
            KeywordDetector(),
        ]
        if use_entropy:
            self._detectors.append(EntropyDetector())

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def scan(self, target: Path) -> List[Finding]:
        """
        Scan *target* (file or directory) and return all findings,
        sorted by (file, line_number).
        """
        findings: List[Finding] = []

        if target.is_file():
            findings.extend(self._scan_file(target, base=target.parent))
        elif target.is_dir():
            for file_path in self._walk(target):
                findings.extend(self._scan_file(file_path, base=target))
        else:
            raise ValueError(f"Target is neither a file nor a directory: {target}")

        # Deduplicate: same file + line + type can be reported by multiple detectors
        seen: Set[tuple] = set()
        unique: List[Finding] = []
        for f in findings:
            key = (f.file_path, f.line_number, f.secret_type)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        unique.sort(key=lambda f: (f.file_path, f.line_number))
        return unique

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _walk(self, root: Path):
        """Yield all scannable files under *root*, skipping excluded dirs."""
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune excluded subdirectories in-place so os.walk doesn't descend
            dirnames[:] = [
                d for d in dirnames
                if d not in self._excluded and not d.startswith(".")
            ]

            for filename in filenames:
                file_path = Path(dirpath) / filename
                if self._is_scannable(file_path):
                    yield file_path

    def _is_scannable(self, path: Path) -> bool:
        """Return True if the file should be scanned."""
        # Excluded by name
        if path.name in self._excluded:
            return False

        # Extension allow-list (also accept files with no extension if small)
        ext = path.suffix.lower()
        if ext and ext not in SUPPORTED_EXTENSIONS:
            if path.name.lower() not in SUPPORTED_EXTENSIONS:
                return False

        # Size guard
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                return False
            if path.stat().st_size == 0:
                return False
        except OSError:
            return False

        return True

    def _scan_file(self, path: Path, base: Path) -> List[Finding]:
        """Read *path* line-by-line and apply all detectors."""
        findings: List[Finding] = []

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return findings

        # Fast binary sniff: reject if NUL bytes present
        if "\x00" in text[:8192]:
            return findings

        relative = str(path.relative_to(base)) if base in path.parents or base == path.parent else str(path)

        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for detector in self._detectors:
                for finding in detector.detect(line, lineno, relative):
                    findings.append(finding)

        return findings
