from __future__ import annotations

import os
from pathlib import Path

from supersonar.models import CoverageData, Issue, ScanResult
from supersonar.rules import GenericRuleEngine, PythonRuleEngine


def _should_exclude(path: Path, excludes: list[str]) -> bool:
    return any(ex in path.parts for ex in excludes)


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

    if root_path.is_file():
        file_candidates = [root_path]
    else:
        file_candidates = []

    for file_path in file_candidates:
        if not _has_allowed_target(file_path, include_ext_set, include_name_set, max_file_size_kb):
            continue
        files_scanned += 1
        try:
            if file_path.suffix.lower() == ".py":
                file_issues = python_engine.run(file_path)
            else:
                file_issues = generic_engine.run(file_path)
        except OSError as exc:
            issues.append(
                Issue(
                    rule_id="SS900",
                    title="File scan error",
                    severity="medium",
                    message=f"Unable to read file during scan: {exc}",
                    file_path=file_path.name,
                    line=1,
                    column=1,
                )
            )
            file_issues = []

        for issue in file_issues:
            issue.file_path = file_path.name
        issues.extend(file_issues)

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=False):
        dir_path = Path(dirpath)
        dirnames[:] = sorted(name for name in dirnames if not _should_exclude(dir_path / name, excludes))
        for filename in sorted(filenames):
            file_path = dir_path / filename
            if _should_exclude(file_path, excludes):
                continue
            if not _has_allowed_target(file_path, include_ext_set, include_name_set, max_file_size_kb):
                continue
            files_scanned += 1
            try:
                if file_path.suffix.lower() == ".py":
                    file_issues = python_engine.run(file_path)
                else:
                    file_issues = generic_engine.run(file_path)
            except OSError as exc:
                relative = _relative_path(file_path, root_path)
                issues.append(
                    Issue(
                        rule_id="SS900",
                        title="File scan error",
                        severity="medium",
                        message=f"Unable to read file during scan: {exc}",
                        file_path=relative,
                        line=1,
                        column=1,
                    )
                )
                continue

            for issue in file_issues:
                issue.file_path = _relative_path(Path(issue.file_path), root_path)
            issues.extend(file_issues)

    deduped = _dedupe_issues(issues)
    return ScanResult(issues=deduped, files_scanned=files_scanned, coverage=coverage)


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def _dedupe_issues(issues: list[Issue]) -> list[Issue]:
    unique: dict[tuple[str, str, int, int, str], Issue] = {}
    for issue in issues:
        key = (issue.file_path, issue.rule_id, issue.line, issue.column, issue.message)
        unique[key] = issue
    return sorted(unique.values(), key=lambda issue: (issue.file_path, issue.line, issue.column, issue.rule_id))
