# Secure Code Analyzer (PHP + JavaScript)
A lightweight static analyzer that detects insecure coding patterns in **PHP** and **JavaScript** with **actionable fixes**, **severity ranking**, and **JSON/HTML reports**.

## Features
- Detects: **SQL Injection**, **XSS**, **Dangerous functions** (`eval`, `exec`), **Weak crypto** (`md5`, `sha1`), **Poor error handling**.
- **Zero dependencies** (pure Python) – easy to run anywhere.
- **CLI tool** with JSON and HTML report output.
- **Rule-based engine** + a few **special detectors** (basic taint-like checks).
- **OWASP Top 10 mapping** in rule metadata.
- Ready-to-use **GitHub Actions** workflow for CI integration.

## Quick Start
```bash
# 1) Run on samples (already included)
python -m src.secure_code_analyzer.cli scan samples --out reports/report.json --html reports/report.html --summary

# 2) Scan your project
python -m src.secure_code_analyzer.cli scan /path/to/code --out reports/report.json --html reports/report.html --summary

# 3) Fail CI when High severity issues exist
python -m src.secure_code_analyzer.cli scan /path/to/code --fail-on HIGH
```

## Outputs
- **JSON**: `reports/report.json` – machine-readable for CI dashboards.
- **HTML**: `reports/report.html` – human-friendly report with filters.

## Extending Rules
Add new entries to `src/secure_code_analyzer/rules/rules.json`. Each rule supports:
```json
{
  "id": "JS-EVAL-001",
  "language": "javascript",
  "category": "Dangerous Function",
  "owasp": "A03:2021-Injection",
  "severity": "HIGH",
  "pattern": "eval\s*\(",
  "message": "Use of eval() can lead to code injection.",
  "suggestion": "Avoid eval(); use JSON.parse or safe parsing/function mapping."
}
```

## CI Integration (GitHub Actions)
Workflow file at `.github/workflows/scan.yml` automatically:
- runs the analyzer on push/PR,
- uploads the JSON/HTML reports as CI artifacts,
- fails the build if **HIGH** issues are found.

## License
MIT
