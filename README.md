# supersonar

`supersonar` is a lightweight, SonarQube-inspired static analysis CLI for multi-language repositories.
It is designed for local use and CI pipelines via `pip install` (Python 3.10+).

## Quick start

```bash
pip install .
supersonar scan . --format json
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
- hardcoded secret-like assignments
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
include_extensions = [".py", ".java", ".js", ".ts", ".go", ".rs", ".cs", ".yaml", ".yml", ".json", ".toml"]
include_filenames = ["Dockerfile", "Jenkinsfile", "Makefile"]
max_file_size_kb = 1024
coverage_xml = "coverage.xml"

[quality_gate]
fail_on = "high"
max_issues = 200
max_high = 0
max_critical = 0
min_coverage = 80.0

[report]
format = "json"
```

Use CLI overrides when needed:

```bash
supersonar scan . --include-ext .java --include-ext .kt --include-file Dockerfile
```

## Quality gates

- `fail_on`: fail if any issue exists at/above severity
- `max_issues`: fail if total issues exceed threshold
- `max_low`, `max_medium`, `max_high`, `max_critical`: per-severity caps
- `min_coverage`: minimum line coverage percentage from Cobertura XML

Generate `coverage.xml` in Python projects with:

```bash
python -m pip install coverage
coverage run -m pytest
coverage xml -o coverage.xml
```
