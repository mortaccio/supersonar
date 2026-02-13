from __future__ import annotations

from pathlib import Path
import re

from supersonar.models import Issue
from supersonar.rules.generic import GenericRuleEngine


PACKAGE_PATTERN = re.compile(r"^\s*package\s+([A-Za-z_]\w*)\s*$")
FUNC_PATTERN = re.compile(r"^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)")
IMPORT_SINGLE_PATTERN = re.compile(r'^\s*import\s+"([^"]+)"\s*$')
IMPORT_BLOCK_START = re.compile(r"^\s*import\s*\(\s*$")
IMPORT_BLOCK_ITEM = re.compile(r'^\s*"([^"]+)"\s*$')
MAX_FUNCTION_PARAMS = 6
MAX_FUNCTION_LINES = 60
MAX_NESTING_DEPTH = 4
MAX_IMPORT_FAN_OUT = 25


class GoRuleEngine:
    def __init__(self) -> None:
        self._generic_engine = GenericRuleEngine()

    def run(self, file_path: Path) -> list[Issue]:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        issues = self._generic_engine.run(file_path)
        issues.extend(self._find_package_naming(source, file_path))
        issues.extend(self._find_function_naming_and_params(source, file_path))
        issues.extend(self._find_function_length(source, file_path))
        issues.extend(self._find_nesting_depth(source, file_path))
        issues.extend(self._find_import_fan_out(source, file_path))
        return issues

    def _find_package_naming(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            match = PACKAGE_PATTERN.search(line)
            if not match:
                continue
            package_name = match.group(1)
            if re.fullmatch(r"[a-z][a-z0-9]*", package_name):
                continue
            issues.append(
                Issue(
                    rule_id="SS401",
                    title="Go package naming convention",
                    severity="low",
                    message="Go package names should be short lowercase identifiers.",
                    file_path=str(file_path),
                    line=idx,
                    column=match.start(1) + 1,
                )
            )
        return issues

    def _find_function_naming_and_params(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            match = FUNC_PATTERN.search(line)
            if not match:
                continue
            name = match.group(1)
            params = match.group(2)
            if "_" in name:
                issues.append(
                    Issue(
                        rule_id="SS402",
                        title="Go function naming convention",
                        severity="low",
                        message="Function names should use CamelCase without underscores.",
                        file_path=str(file_path),
                        line=idx,
                        column=match.start(1) + 1,
                    )
                )
            param_count = _count_go_params(params)
            if param_count > MAX_FUNCTION_PARAMS:
                issues.append(
                    Issue(
                        rule_id="SS403",
                        title="Go function has too many parameters",
                        severity="medium",
                        message=f"Function has {param_count} parameters; target at most {MAX_FUNCTION_PARAMS}.",
                        file_path=str(file_path),
                        line=idx,
                        column=match.start(1) + 1,
                    )
                )
        return issues

    def _find_function_length(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        lines = source.splitlines()
        idx = 0
        while idx < len(lines):
            line = lines[idx]
            match = FUNC_PATTERN.search(line)
            if not match or "{" not in line:
                idx += 1
                continue
            depth = line.count("{") - line.count("}")
            end_idx = idx
            while depth > 0 and end_idx + 1 < len(lines):
                end_idx += 1
                depth += lines[end_idx].count("{")
                depth -= lines[end_idx].count("}")
            fn_lines = end_idx - idx + 1
            if fn_lines > MAX_FUNCTION_LINES:
                issues.append(
                    Issue(
                        rule_id="SS404",
                        title="Go function too long",
                        severity="medium",
                        message=f"Function spans {fn_lines} lines; target at most {MAX_FUNCTION_LINES}.",
                        file_path=str(file_path),
                        line=idx + 1,
                        column=match.start(1) + 1,
                    )
                )
            idx = end_idx + 1
        return issues

    def _find_nesting_depth(self, source: str, file_path: Path) -> list[Issue]:
        depth = 0
        max_depth = 0
        for line in source.splitlines():
            depth += line.count("{")
            max_depth = max(max_depth, max(0, depth - 1))
            depth -= line.count("}")
        if max_depth <= MAX_NESTING_DEPTH:
            return []
        return [
            Issue(
                rule_id="SS405",
                title="Go nesting depth too high",
                severity="medium",
                message=f"Maximum block nesting depth is {max_depth}; keep it at or below {MAX_NESTING_DEPTH}.",
                file_path=str(file_path),
                line=1,
                column=1,
            )
        ]

    def _find_import_fan_out(self, source: str, file_path: Path) -> list[Issue]:
        imports = _collect_go_imports(source.splitlines())
        if len(imports) <= MAX_IMPORT_FAN_OUT:
            return []
        return [
            Issue(
                rule_id="SS406",
                title="Go import fan-out too high",
                severity="medium",
                message=f"File imports {len(imports)} dependencies; consider reducing coupling.",
                file_path=str(file_path),
                line=1,
                column=1,
            )
        ]


def _count_go_params(params: str) -> int:
    text = params.strip()
    if not text:
        return 0
    parts = [part.strip() for part in text.split(",") if part.strip()]
    return len(parts)


def _collect_go_imports(lines: list[str]) -> set[str]:
    imports: set[str] = set()
    in_block = False
    for line in lines:
        if IMPORT_BLOCK_START.search(line):
            in_block = True
            continue
        if in_block:
            if line.strip() == ")":
                in_block = False
                continue
            block_match = IMPORT_BLOCK_ITEM.search(line)
            if block_match:
                imports.add(block_match.group(1))
            continue
        single_match = IMPORT_SINGLE_PATTERN.search(line)
        if single_match:
            imports.add(single_match.group(1))
    return imports
