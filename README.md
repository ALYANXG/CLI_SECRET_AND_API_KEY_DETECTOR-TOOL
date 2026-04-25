# Secret & API Key Detector

Production-ready Python CLI that scans files and directories for hardcoded secrets before they are committed.

## What This Tool Does

- Detects known secret formats with regex (AWS, GitHub, Stripe, Slack, JWT, private keys, etc.)
- Detects risky assignments with keyword heuristics (`password`, `api_key`, `secret_key`)
- Detects suspicious high-entropy strings
- Masks sensitive values in output (for example: `sk_l***1234`)
- Exits with code `1` when findings are present (CI/CD friendly)

---

## Project Structure

```text
secret-detector/
├── main.py
├── models.py
├── detectors/
│   ├── regex_detector.py
│   └── keyword_detector.py
├── scanner/
│   ├── file_scanner.py
│   └── entropy_detector.py
├── reporter/
│   └── report_generator.py
├── tests/
│   ├── test_detectors.py
│   └── fixtures/example_secrets.env
├── requirements.txt
├── Dockerfile
├── .dockerignore
└── .gitignore
```

---

## Requirements

- Python `3.10+`
- Optional: Docker Desktop

---

## Quick Start (Local)

### 1) Clone repo

```bash
git clone <your-repo-url>
cd secret-detector
```

### 2) Install dependencies

```bash
py -3 -m pip install -r requirements.txt
```

> Linux/macOS: use `python3` instead of `py -3`.

### 3) Run tests

```bash
py -3 -m pytest tests -q
```

### 4) Run scan

```bash
py -3 main.py scan .
```

---

## CLI Usage

```bash
py -3 main.py scan <path> [options]
```

### Options

- `--json` output report in JSON
- `--severity <low|medium|high|critical>` minimum severity filter
- `--no-entropy` disable entropy detector
- `--exclude <name1 name2 ...>` skip files/folders by name
- `--output <file>` write report to file

### Useful Examples

```bash
# Scan current directory
py -3 main.py scan .

# Scan one file
py -3 main.py scan tests/fixtures/example_secrets.env

# JSON report
py -3 main.py scan . --json --output report.json

# Scan only high+ findings
py -3 main.py scan . --severity high

# Cleaner scan (exclude noise)
py -3 main.py scan . --exclude tests .pytest_cache __pycache__ .git

# Faster scan (disable entropy)
py -3 main.py scan . --no-entropy
```

---

## Docker Usage

### 1) Build image

```bash
docker build -t secret-detector:latest .
```

### 2) Scan current project

```bash
docker run --rm -v "${PWD}:/work" secret-detector:latest scan /work
```

### 3) Cleaner Docker scan

```bash
docker run --rm -v "${PWD}:/work" secret-detector:latest scan /work --exclude .git .pytest_cache __pycache__ tests/fixtures --severity high
```

### 4) JSON report from Docker

```bash
docker run --rm -v "${PWD}:/work" secret-detector:latest scan /work --json --output /work/report.json
```

---

## How It Works

1. `main.py` parses CLI arguments.
2. `FileScanner` traverses target files/directories.
3. Each line is passed to:
   - `RegexDetector`
   - `KeywordDetector`
   - `EntropyDetector` (unless disabled)
4. Findings are stored as `Finding` objects from `models.py`.
5. `ReportGenerator` outputs:
   - human table mode, or
   - machine JSON mode.
6. Exit codes:
   - `0` no findings
   - `1` findings detected
   - `2` usage/runtime error

---

## CI/CD Example (GitHub Actions)

```yaml
name: Secret Scan

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -r requirements.txt
      - run: python main.py scan . --severity high --json --output secret-report.json
      - uses: actions/upload-artifact@v4
        with:
          name: secret-report
          path: secret-report.json
```

---

## GitHub Upload (Step-by-Step)

If project is new:

```bash
git init
git add .
git commit -m "Initial commit: secret detector"
git branch -M main
git remote add origin https://github.com/<username>/<repo>.git
git push -u origin main
```

If project already linked to remote:

```bash
git add .
git commit -m "Docs and Docker improvements"
git push
```

---

## Release Checklist (Before Push)

- [ ] `py -3 -m pytest tests -q` passes
- [ ] `py -3 main.py scan . --exclude tests .pytest_cache __pycache__ .git --severity high` runs
- [ ] `docker build -t secret-detector:latest .` succeeds
- [ ] Docker scan command runs successfully
- [ ] `README.md` commands validated
- [ ] `.gitignore` excludes cache/build/report files
- [ ] No real credentials committed in repository

---

## Security Notes

- Scanner does not print raw secrets
- Scanner is read-only on scanned files
- Scanner makes no external network calls for detection logic

---

## License

MIT
# Secret & API Key Detector

Production-ready Python CLI that scans files/folders for hardcoded secrets before they are committed.

## What This Tool Does

- Detects common secret formats with regex (AWS, GitHub, Stripe, Slack, OpenAI, JWT, private keys, etc.)
- Detects risky assignments with keyword heuristics (`password =`, `api_key =`, `secret_key =`)
- Detects suspicious high-entropy tokens (unknown random-looking strings)
- Masks all sensitive values in output (`sk_l***1234`) to avoid leaking secrets
- Returns exit code `1` if findings exist (ideal for CI/CD and pre-commit)

---

## Project Structure

```text
secret-detector/
├── main.py
├── models.py
├── detectors/
│   ├── regex_detector.py
│   └── keyword_detector.py
├── scanner/
│   ├── file_scanner.py
│   └── entropy_detector.py
├── reporter/
│   └── report_generator.py
├── tests/
│   ├── test_detectors.py
│   └── fixtures/example_secrets.env
├── requirements.txt
├── Dockerfile
└── .dockerignore
```

---

## Requirements

- Python `3.10+`
- (Optional) Docker Desktop for containerized usage

---

## Quick Start (Local)

### 1) Clone and enter project

```bash
git clone <your-repo-url>
cd secret-detector
```

### 2) Install dependencies

```bash
py -3 -m pip install -r requirements.txt
```

> On Linux/macOS use `python3` instead of `py -3`.

### 3) Run tests

```bash
py -3 -m pytest tests -q
```

### 4) Run scanner

```bash
py -3 main.py scan .
```

---

## CLI Usage

```bash
py -3 main.py scan <path> [options]
```

### Arguments

- `<path>`: file or directory to scan

### Options

- `--json`: output JSON
- `--severity <low|medium|high|critical>`: minimum severity filter
- `--no-entropy`: disable entropy detection
- `--exclude <name1 name2 ...>`: skip directories/files by name
- `--output <file>`: write report to file

### Examples

```bash
# Scan current directory
py -3 main.py scan .

# Scan one file
py -3 main.py scan tests/fixtures/example_secrets.env

# Only critical findings
py -3 main.py scan . --severity critical

# JSON report for CI
py -3 main.py scan . --json --output report.json

# Exclude noisy folders
py -3 main.py scan . --exclude tests .pytest_cache __pycache__

# Faster scan (skip entropy)
py -3 main.py scan . --no-entropy
```

---

## Docker Usage

### 1) Build image

```bash
docker build -t secret-detector:latest .
```

### 2) Run scan on current project

```bash
docker run --rm -v "${PWD}:/work" secret-detector:latest scan /work
```

### 3) JSON output to mounted file

```bash
docker run --rm -v "${PWD}:/work" secret-detector:latest scan /work --json --output /work/report.json
```

### 4) Windows PowerShell mount example

```powershell
docker run --rm -v "${PWD}:/work" secret-detector:latest scan /work --exclude .git .venv node_modules
```

---

## CI/CD Integration

Because this tool exits with `1` when findings are detected, it naturally blocks insecure changes.

### GitHub Actions example

```yaml
name: Secret Scan

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -r requirements.txt
      - run: python main.py scan . --severity high --json --output secret-report.json
      - uses: actions/upload-artifact@v4
        with:
          name: secret-report
          path: secret-report.json
```

---

## How It Works Internally

1. `main.py` parses CLI flags and validates target path.
2. `FileScanner` recursively traverses files, skipping binaries and excluded names.
3. For each line, three detectors are executed:
   - `RegexDetector`
   - `KeywordDetector`
   - `EntropyDetector` (if enabled)
4. Findings are normalized into `Finding` objects (`models.py`).
5. `ReportGenerator` produces table or JSON output with masked values only.
6. Exit code:
   - `0`: no findings
   - `1`: findings present
   - `2`: runtime/usage error

---

## False Positive Reduction Tips

- Use `--exclude` for generated/vendor/test fixture directories
- Use `--severity high` for stricter results
- Use `--no-entropy` if random non-secret strings are noisy

Recommended cleaner repo scan:

```bash
py -3 main.py scan . --exclude tests .pytest_cache __pycache__ .git --severity high
```

---

## Upload To GitHub (Step-by-Step)

If this project is not pushed yet:

```bash
git init
git add .
git commit -m "Initial commit: secret detector with Docker support"
git branch -M main
git remote add origin https://github.com/<username>/<repo>.git
git push -u origin main
```

If repo already exists locally, only do:

```bash
git add .
git commit -m "Improve README and add Docker support"
git push
```

---

## Security Notes

- No outbound network calls from scanner logic
- No raw secret values printed to terminal output
- Read-only scan behavior (does not modify scanned files)

---

## License

MIT
# Secret & API Key Detector

A production-ready CLI tool that scans codebases for hardcoded secrets, API keys, tokens, and passwords — before they reach version control.

```
╔══════════════════════════════════════════════╗
║        Secret & API Key Detector             ║
╚══════════════════════════════════════════════╝

  📄 config/settings.py
  ──────────────────────────────────────────────────────────────────────
    🔴 CRITICAL  L14    AWS Access Key ID
                 [regex] Value: AKIA***MPLE

    🟠 HIGH      L22    Hardcoded Password
                 [keyword] Value: Supe***d99!

  ══════════════════════════════════════════════
  FINAL SUMMARY
  Total findings : 2
  Files affected : 1

  By severity:
    🔴  CRITICAL    1
    🟠  HIGH        1
```

---

## Features

| Feature | Details |
|---|---|
| **Regex detection** | 30+ patterns: AWS, GitHub, Stripe, Slack, JWT, SSH keys, OpenAI, Anthropic, and more |
| **Entropy detection** | Shannon entropy analysis catches unknown high-randomness tokens |
| **Keyword detection** | Variable-name heuristics (`api_key = "..."`, `password = "..."`) |
| **Safe output** | Secrets are always masked — no raw values are printed |
| **JSON mode** | Machine-readable output for CI/CD pipelines |
| **Severity levels** | `critical` / `high` / `medium` / `low` with colour coding |
| **Fast traversal** | Binary files skipped; configurable excludes; 5 MB file cap |
| **Zero dependencies** | Standard library only (pytest for tests) |

---

## Installation

### Option A — Run directly

```bash
git clone https://github.com/yourusername/secret-detector.git
cd secret-detector
pip install -r requirements.txt   # only needed for tests
python main.py scan .
```

### Option B — Install as a CLI command

```bash
pip install -e .          # after adding setup.py / pyproject.toml
secret-detector scan .
```

> **Python version**: 3.10 or later (uses `str | None` union syntax).

---

## Usage

```
secret-detector scan <path> [options]
```

### Positional arguments

| Argument | Description |
|---|---|
| `<path>` | File or directory to scan |

### Options

| Flag | Description |
|---|---|
| `--json` | Output results in JSON format |
| `--severity <level>` | Filter to `low` / `medium` / `high` / `critical` |
| `--no-entropy` | Disable entropy-based detection |
| `--exclude <dir>…` | Additional directories/files to skip |
| `--output <file>` | Write results to a file instead of stdout |

### Examples

```bash
# Scan the current directory
python main.py scan .

# Scan a single file
python main.py scan config/.env

# CI mode — JSON output, exit 1 if any secrets found
python main.py scan ./src --json

# Only show critical findings
python main.py scan . --severity critical

# Exclude test fixtures and vendor code
python main.py scan . --exclude tests/fixtures vendor

# Save a JSON report to disk
python main.py scan . --json --output report.json

# Skip entropy detection (faster, fewer false positives)
python main.py scan . --no-entropy
```

---

## Detected Secret Types

### Regex-based (exact pattern matches)

| Type | Severity |
|---|---|
| AWS Access Key ID | 🔴 Critical |
| AWS Secret Access Key | 🔴 Critical |
| Google API Key | 🔴 Critical |
| GitHub Personal Access Token | 🔴 Critical |
| GitLab Personal Access Token | 🔴 Critical |
| Stripe Live Secret Key | 🔴 Critical |
| Slack Token / Webhook | 🔴 Critical / 🟠 High |
| SendGrid API Key | 🔴 Critical |
| OpenAI API Key | 🔴 Critical |
| Anthropic API Key | 🔴 Critical |
| HuggingFace API Token | 🔴 Critical |
| Discord Bot Token | 🔴 Critical |
| Telegram Bot Token | 🔴 Critical |
| npm Access Token | 🔴 Critical |
| PyPI API Token | 🔴 Critical |
| SSH / RSA Private Key Block | 🔴 Critical |
| Database Connection String | 🔴 Critical |
| JWT Token | 🟠 High |
| Hardcoded Password | 🟠 High |
| Stripe Test Key | 🟠 High |
| Generic API Key / Token | 🟠 High |

### Entropy-based (statistical analysis)

| Type | Severity |
|---|---|
| High-Entropy Base64 String | 🟡 Medium |
| High-Entropy Hex String | 🟡 Medium |

### Keyword-based (variable name heuristics)

| Type | Severity |
|---|---|
| `private_key`, `secret_key` assignments | 🔴 Critical |
| `db_password`, `database_password` | 🔴 Critical |
| `password`, `passwd`, `api_key` | 🟠 High |
| `token`, `auth_token`, `secret` | 🟠 High |
| Generic `credential` | 🟡 Medium |

---

## Architecture

```
secret-detector/
│
├── main.py                     ← CLI entry point (argparse)
│
├── models.py                   ← Finding dataclass (shared data model)
│
├── scanner/
│   ├── file_scanner.py         ← Directory traversal + detector orchestration
│   └── entropy_detector.py     ← Shannon entropy analysis
│
├── detectors/
│   ├── regex_detector.py       ← 30+ compiled regex patterns
│   └── keyword_detector.py     ← Variable-name heuristics
│
├── reporter/
│   └── report_generator.py     ← Table + JSON output rendering
│
├── tests/
│   ├── test_detectors.py       ← Unit + integration tests
│   └── fixtures/
│       └── example_secrets.env ← Fake secrets for testing
│
├── requirements.txt
└── README.md
```

### Module responsibilities

| Module | Role |
|---|---|
| `main.py` | Parses CLI args, wires together scanner + reporter |
| `models.py` | `Finding` dataclass — the only data structure passed between modules |
| `FileScanner` | Walks paths, filters files, calls all detectors per line |
| `RegexDetector` | Matches 30+ compiled patterns; extracts + masks capture group |
| `KeywordDetector` | Identifies risky variable assignments by name |
| `EntropyDetector` | Flags high-entropy tokens with Shannon entropy analysis |
| `ReportGenerator` | Renders coloured table or structured JSON; never prints raw values |

---

## CI/CD Integration

The tool exits with code `1` when any findings are present, making it ideal for pre-commit hooks and CI pipelines.

### GitHub Actions

```yaml
- name: Scan for secrets
  run: python main.py scan . --severity high --json --output secret-report.json

- name: Upload report
  uses: actions/upload-artifact@v3
  with:
    name: secret-scan-report
    path: secret-report.json
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secret-detector
        name: Secret Detector
        entry: python main.py scan
        language: python
        pass_filenames: true
```

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=. --cov-report=term-missing

# Run a specific test class
pytest tests/test_detectors.py::TestRegexDetector -v
```

---

## JSON Output Format

```json
{
  "scan_timestamp": "2025-04-21T10:00:00+00:00",
  "summary": {
    "total": 3,
    "files_affected": 2,
    "by_severity": {
      "critical": 2,
      "high": 1
    },
    "by_detector": {
      "regex": 2,
      "keyword": 1
    }
  },
  "findings": [
    {
      "file": "config/settings.py",
      "line": 14,
      "type": "AWS Access Key ID",
      "detector": "regex",
      "severity": "critical",
      "value": "AKIA***MPLE"
    }
  ]
}
```

---

## False Positives

The tool applies several false-positive reduction strategies:

1. **Placeholder filter** — ignores values like `your_api_key_here`, `<TOKEN>`, `${MY_SECRET}`
2. **Minimum length** — keyword detector requires ≥ 6 character values
3. **Comment skip** — entropy detector skips comment lines
4. **Entropy threshold** — entropy detector uses empirically tuned thresholds
5. **`--no-entropy`** — disable entropy detection if noise is too high

If you find a persistent false positive, add the pattern to `FP_PATTERNS` in `detectors/regex_detector.py`.

---

## Security Notes

- **No secrets are logged** — only masked versions (`sk_l***ey`) appear in output
- **No network calls** — entirely offline, no telemetry
- **No database** — stateless; results exist only for the duration of a run
- **Read-only** — the tool never modifies scanned files

---

## Contributing

1. Fork the repo
2. Add new patterns to `PATTERNS` in `detectors/regex_detector.py`
3. Add a corresponding test to `tests/test_detectors.py`
4. Run `pytest tests/ -v` — all tests must pass
5. Open a pull request

---

## License

MIT — see `LICENSE` for details.
