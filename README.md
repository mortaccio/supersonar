# supersonar

`supersonar` is a lightweight, static analysis CLI for multi-language repositories.
It is designed for local use and CI pipelines via `pip install` (Python 3.10+).

## Project Description

`supersonar` is a production-focused static analysis CLI for mixed repositories (backend, frontend, and infrastructure).
It scans source code and deployment artifacts (including Dockerfile and Kubernetes manifests), produces JSON/SARIF reports,
and can enforce security quality gates in CI/CD before deployment.

## Supported Languages

- Python
- Java
- Kotlin
- JavaScript / React (`.js`, `.jsx`, `.ts`, `.tsx`)
- Go

## Quick start

```bash
pip install .
supersonar scan . --format json
supersonar scan . --pretty
```

## Pipeline install (pip)

Use an isolated environment in CI:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install supersonar
supersonar --version
supersonar scan . --format sarif --out reports/supersonar.sarif
```

Or install from repository source directly:

```bash
python -m pip install "git+https://github.com/mortaccio/supersonar.git@main"
```

The scanner performs real code checks (AST + regex), including:
- dynamic execution (`eval`/`exec`)
- broad exception handlers
- `subprocess.*(..., shell=True)` in Python
- unsafe `yaml.load(...)` in Python
- unsafe `pickle.load/loads(...)` in Python
- `requests(..., verify=False)` in Python
- cross-language readability checks (line too long, trailing whitespace, oversized file)
- duplicate-code block detection (repeated multi-line chunks)
- Java package naming convention checks (`lower.case.package`)
- Java type naming convention checks (`UpperCamelCase`)
- Java class/file naming consistency checks (`MyClass` in `MyClass.java`)
- Java method naming convention checks (`lowerCamelCase`)
- Java constant naming convention checks (`UPPER_SNAKE_CASE`)
- Java complexity checks (too many method parameters, very long methods, deep nesting)
- Java coupling/cohesion checks (high import fan-out, classes with too many methods, low cohesion)
- Java command execution usage (`Runtime.exec`, `ProcessBuilder`)
- Kotlin checks (package/type/function naming, too many parameters, long functions, deep nesting)
- Kotlin command execution usage (`Runtime.exec`, `ProcessBuilder`)
- Python naming checks (snake_case functions, UpperCamelCase classes)
- Python complexity checks (too many parameters, very long functions, deep nesting)
- Python coupling/cohesion checks (high import fan-out, classes with too many methods, low cohesion)
- JavaScript/React checks (function/component naming, too many parameters, long functions, deep nesting)
- Node.js command execution usage (`child_process.exec/execSync`)
- Go checks (package/function naming, too many parameters, long functions, deep nesting, import fan-out)
- Go security checks (`InsecureSkipVerify: true`, `exec.Command("sh", "-c", ...)`)
- hardcoded secret-like assignments
- insecure external `http://` endpoint literals
- Dockerfile hardening checks (root user, unpinned image tags, curl/wget piped to shell)
- Kubernetes manifest checks (privileged containers, privilege escalation, root policies, host namespace sharing)
- private key block markers (for example `BEGIN ... PRIVATE KEY`)
- TODO/FIXME markers
- unresolved merge conflict markers

Python files use AST rules. Other file types use generic cross-language text rules.

## CI usage

```bash
pip install supersonar
supersonar scan . \
  --format sarif \
  --out reports/supersonar.sarif \
  --fail-on high \
  --max-high 0 \
  --max-critical 0 \
  --coverage-xml coverage.xml \
  --min-coverage 80
```

## Config (`supersonar.toml`)

```toml
[scan]
exclude = [".git", ".venv", "venv", "build", "dist", "__pycache__"]
include_extensions = [".py", ".java", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".cs", ".yaml", ".yml", ".json", ".toml"]
include_filenames = ["Dockerfile", "Jenkinsfile", "Makefile"]
max_file_size_kb = 1024
skip_generated = true
inline_ignore = true
security_only = false
disabled_rules = []
# enabled_rules = ["SS001", "SS003"]
coverage_xml = "coverage.xml"

[quality_gate]
fail_on = "high"
max_issues = 200
max_files_with_issues = 25
max_high = 0
max_critical = 0
min_coverage = 80.0
baseline_report = "reports/supersonar-baseline.json"
only_new_issues = true

[report]
format = "json"
```

Use CLI overrides when needed:

```bash
supersonar scan . --include-ext .java --include-ext .kt --include-file Dockerfile
supersonar scan . --security-only
supersonar scan . --pretty
supersonar scan . --security-only --format json --out reports/security-report.json
```

## Quality gates

- `fail_on`: fail if any issue exists at/above severity
- `max_issues`: fail if total issues exceed threshold
- `max_files_with_issues`: fail if number of files with at least one issue exceeds threshold
- `max_low`, `max_medium`, `max_high`, `max_critical`: per-severity caps
- `min_coverage`: minimum line coverage percentage from Cobertura XML
- `baseline_report` + `only_new_issues`: gate only on issues not present in a previous report

Generate `coverage.xml` in Python projects with:

```bash
python -m pip install coverage
coverage run -m pytest
coverage xml -o coverage.xml
```

## Noise control

- Generated artifacts are skipped by default (`target/`, `.mypy_cache/`, `.pytest_cache/`, `.tox/`, `.nox/`, `.gradle/`, `node_modules/`, and common binary suffixes).
- Use `--include-generated` when you explicitly want to scan generated/build outputs.
- Inline suppression is supported per line:
  - `# supersonar:ignore` ignores all rules on that line.
  - `# supersonar:ignore SS001,SS007` ignores specific rules on that line.
- Rule-level controls:
  - `--disable-rule SS004` (repeatable)
  - `--enable-rule SS001 --enable-rule SS003` (allowlist mode)
