from __future__ import annotations

from pathlib import Path

from supersonar.models import CoverageData, Issue, ScanResult
from supersonar.rules import GenericRuleEngine, PythonRuleEngine


def _should_exclude(path: Path, excludes: list[str]) -> bool:
    parts = set(path.parts)
    return any(ex in parts for ex in excludes)


def _has_allowed_target(
    path: Path,
    include_extensions: set[str],
    include_filenames: set[str],
    max_file_size_kb: int,
) -> bool:
    if not path.is_file():
        return False
    if max_file_size_kb > 0 and path.stat().st_size > max_file_size_kb * 1024:
        return False
    if path.name in include_filenames:
        return True
    return path.suffix.lower() in include_extensions


def scan_path(
    root: str,
    excludes: list[str],
    include_extensions: list[str],
    include_filenames: list[str],
    max_file_size_kb: int,
    coverage: CoverageData | None = None,
) -> ScanResult:
    root_path = Path(root).resolve()
    python_engine = PythonRuleEngine()
    generic_engine = GenericRuleEngine()
    issues: list[Issue] = []
    files_scanned = 0
    include_ext_set = {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in include_extensions}
    include_name_set = set(include_filenames)

    for file_path in root_path.rglob("*"):
        if _should_exclude(file_path, excludes):
            continue
        if not _has_allowed_target(file_path, include_ext_set, include_name_set, max_file_size_kb):
            continue
        files_scanned += 1
        if file_path.suffix.lower() == ".py":
            issues.extend(python_engine.run(file_path))
        else:
            issues.extend(generic_engine.run(file_path))

    return ScanResult(issues=issues, files_scanned=files_scanned, coverage=coverage)
