from __future__ import annotations

import os
from pathlib import Path
import re

from supersonar.models import CoverageData, Issue, ScanResult
from supersonar.rules import GenericRuleEngine, PythonRuleEngine

INLINE_IGNORE_PATTERN = re.compile(r"supersonar:ignore(?:\s+([A-Za-z0-9_, -]+))?", re.IGNORECASE)
GENERATED_DIR_NAMES = {
    "target",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".nox",
    ".ruff_cache",
    "node_modules",
    ".gradle",
    ".eggs",
}
GENERATED_FILE_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".class",
    ".jar",
    ".war",
    ".whl",
    ".egg-info",
    ".min.js",
    ".map",
}


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
    skip_generated: bool = True,
    enabled_rules: list[str] | None = None,
    disabled_rules: list[str] | None = None,
    inline_ignore: bool = True,
) -> ScanResult:
    root_path = Path(root).resolve()
    python_engine = PythonRuleEngine()
    generic_engine = GenericRuleEngine()
    issues: list[Issue] = []
    files_scanned = 0
    include_ext_set = {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in include_extensions}
    include_name_set = set(include_filenames)
    enabled_rule_set = set(enabled_rules) if enabled_rules else None
    disabled_rule_set = set(disabled_rules or [])
    inline_ignore_cache: dict[str, dict[int, set[str]]] = {}

    if root_path.is_file():
        file_candidates = [root_path]
    else:
        file_candidates = []

    for file_path in file_candidates:
        if skip_generated and _is_generated_path(file_path):
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

        filtered = _filter_issues(
            file_issues=file_issues,
            normalized_file_path=file_path.name,
            enabled_rules=enabled_rule_set,
            disabled_rules=disabled_rule_set,
            inline_ignore=inline_ignore,
            inline_ignore_cache=inline_ignore_cache,
            source_file_path=file_path,
        )
        issues.extend(filtered)

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=False):
        dir_path = Path(dirpath)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if not _should_exclude(dir_path / name, excludes)
            and not (skip_generated and _is_generated_path(dir_path / name))
        )
        for filename in sorted(filenames):
            file_path = dir_path / filename
            if _should_exclude(file_path, excludes):
                continue
            if skip_generated and _is_generated_path(file_path):
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

            filtered = _filter_issues(
                file_issues=file_issues,
                normalized_file_path=_relative_path(Path(file_path), root_path),
                enabled_rules=enabled_rule_set,
                disabled_rules=disabled_rule_set,
                inline_ignore=inline_ignore,
                inline_ignore_cache=inline_ignore_cache,
                source_file_path=file_path,
            )
            issues.extend(filtered)

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


def _is_generated_path(path: Path) -> bool:
    if any(part in GENERATED_DIR_NAMES for part in path.parts):
        return True
    if any(part.endswith(".egg-info") for part in path.parts):
        return True
    name_lower = path.name.lower()
    if any(name_lower.endswith(suffix) for suffix in GENERATED_FILE_SUFFIXES):
        return True
    if "target" in path.parts and "generated-sources" in path.parts:
        return True
    return False


def _filter_issues(
    file_issues: list[Issue],
    normalized_file_path: str,
    enabled_rules: set[str] | None,
    disabled_rules: set[str],
    inline_ignore: bool,
    inline_ignore_cache: dict[str, dict[int, set[str]]],
    source_file_path: Path,
) -> list[Issue]:
    allowed: list[Issue] = []
    inline_map = _get_inline_ignore_map(source_file_path, inline_ignore_cache) if inline_ignore else {}

    for issue in file_issues:
        issue.file_path = normalized_file_path
        if issue.rule_id in disabled_rules:
            continue
        if enabled_rules is not None and issue.rule_id not in enabled_rules:
            continue
        ignored_rules = inline_map.get(issue.line)
        if ignored_rules is not None and ("*" in ignored_rules or issue.rule_id in ignored_rules):
            continue
        allowed.append(issue)
    return allowed


def _get_inline_ignore_map(
    source_file_path: Path, inline_ignore_cache: dict[str, dict[int, set[str]]]
) -> dict[int, set[str]]:
    key = str(source_file_path)
    if key in inline_ignore_cache:
        return inline_ignore_cache[key]

    rule_map: dict[int, set[str]] = {}
    try:
        source = source_file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        inline_ignore_cache[key] = rule_map
        return rule_map

    for idx, line in enumerate(source.splitlines(), start=1):
        match = INLINE_IGNORE_PATTERN.search(line)
        if not match:
            continue
        rules = match.group(1)
        if rules is None:
            rule_map[idx] = {"*"}
            continue
        parsed = {token.strip().upper() for token in rules.split(",") if token.strip()}
        rule_map[idx] = parsed if parsed else {"*"}

    inline_ignore_cache[key] = rule_map
    return rule_map
