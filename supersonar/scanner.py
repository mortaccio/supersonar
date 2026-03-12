from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
import re

from supersonar.models import CoverageData, Issue, ScanResult
from supersonar.rules import GoRuleEngine, GenericRuleEngine, JavaRuleEngine, JavaScriptRuleEngine, KotlinRuleEngine, PythonRuleEngine

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
ProgressCallback = Callable[[int, int, str], None]


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
    progress_callback: ProgressCallback | None = None,
) -> ScanResult:
    root_path = Path(root).resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Scan path not found: {root_path}")
    python_engine = PythonRuleEngine()
    java_engine = JavaRuleEngine()
    kotlin_engine = KotlinRuleEngine()
    javascript_engine = JavaScriptRuleEngine()
    go_engine = GoRuleEngine()
    generic_engine = GenericRuleEngine()
    issues: list[Issue] = []
    files_scanned = 0
    include_ext_set = {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in include_extensions}
    include_name_set = set(include_filenames)
    enabled_rule_set = set(enabled_rules) if enabled_rules else None
    disabled_rule_set = set(disabled_rules or [])
    inline_ignore_cache: dict[str, dict[int, set[str]]] = {}
    scan_targets = _collect_scan_targets(
        root_path=root_path,
        excludes=excludes,
        include_extensions=include_ext_set,
        include_filenames=include_name_set,
        max_file_size_kb=max_file_size_kb,
        skip_generated=skip_generated,
    )
    root_is_file = root_path.is_file()

    for index, file_path in enumerate(scan_targets, start=1):
        normalized_file_path = file_path.name if root_is_file else _relative_path(file_path, root_path)
        files_scanned += 1
        try:
            file_issues = _run_file_rules(
                file_path=file_path,
                python_engine=python_engine,
                java_engine=java_engine,
                kotlin_engine=kotlin_engine,
                javascript_engine=javascript_engine,
                go_engine=go_engine,
                generic_engine=generic_engine,
            )
        except OSError as exc:
            issues.append(
                Issue(
                    rule_id="SS900",
                    title="File scan error",
                    severity="medium",
                    message=f"Unable to read file during scan: {exc}",
                    file_path=normalized_file_path,
                    line=1,
                    column=1,
                )
            )
            file_issues = []

        filtered = _filter_issues(
            file_issues=file_issues,
            normalized_file_path=normalized_file_path,
            enabled_rules=enabled_rule_set,
            disabled_rules=disabled_rule_set,
            inline_ignore=inline_ignore,
            inline_ignore_cache=inline_ignore_cache,
            source_file_path=file_path,
        )
        issues.extend(filtered)
        if progress_callback is not None:
            progress_callback(index, len(scan_targets), normalized_file_path)

    deduped = _dedupe_issues(issues)
    return ScanResult(issues=deduped, files_scanned=files_scanned, coverage=coverage)


def _collect_scan_targets(
    root_path: Path,
    excludes: list[str],
    include_extensions: set[str],
    include_filenames: set[str],
    max_file_size_kb: int,
    skip_generated: bool,
) -> list[Path]:
    if root_path.is_file():
        if skip_generated and _is_generated_path(root_path):
            return []
        if not _has_allowed_target(root_path, include_extensions, include_filenames, max_file_size_kb):
            return []
        return [root_path]

    scan_targets: list[Path] = []
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
            if not _has_allowed_target(file_path, include_extensions, include_filenames, max_file_size_kb):
                continue
            scan_targets.append(file_path)
    return scan_targets


def _run_file_rules(
    file_path: Path,
    python_engine: PythonRuleEngine,
    java_engine: JavaRuleEngine,
    kotlin_engine: KotlinRuleEngine,
    javascript_engine: JavaScriptRuleEngine,
    go_engine: GoRuleEngine,
    generic_engine: GenericRuleEngine,
) -> list[Issue]:
    suffix = file_path.suffix.lower()
    if suffix == ".py":
        return python_engine.run(file_path)
    if suffix == ".java":
        return java_engine.run(file_path)
    if suffix == ".kt":
        return kotlin_engine.run(file_path)
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return javascript_engine.run(file_path)
    if suffix == ".go":
        return go_engine.run(file_path)
    return generic_engine.run(file_path)


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
