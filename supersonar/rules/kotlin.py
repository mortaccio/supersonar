from __future__ import annotations

from pathlib import Path
import re

from supersonar.models import Issue
from supersonar.rules.generic import GenericRuleEngine


PACKAGE_PATTERN = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)\s*$")
TYPE_PATTERN = re.compile(
    r"^\s*(?:public|private|internal|protected|abstract|open|sealed|data|enum|annotation|value|inline|companion|\s)*"
    r"(?:class|interface|object|enum\s+class)\s+([A-Za-z_]\w*)\b"
)
FUNCTION_PATTERN = re.compile(r"^\s*(?:suspend\s+)?fun\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
KOTLIN_COMMAND_EXEC_PATTERN = re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(")
KOTLIN_PROCESS_BUILDER_PATTERN = re.compile(r"\bProcessBuilder\s*\(")
MAX_FUNCTION_PARAMS = 6
MAX_FUNCTION_LINES = 60
MAX_NESTING_DEPTH = 4


class KotlinRuleEngine:
    def __init__(self) -> None:
        self._generic_engine = GenericRuleEngine()

    def run(self, file_path: Path) -> list[Issue]:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        issues = self._generic_engine.run(file_path)
        issues.extend(self._find_package_naming(source, file_path))
        issues.extend(self._find_type_naming(source, file_path))
        issues.extend(self._find_function_naming_and_params(source, file_path))
        issues.extend(self._find_function_length(source, file_path))
        issues.extend(self._find_nesting_depth(source, file_path))
        issues.extend(self._find_command_execution(source, file_path))
        return issues

    def _find_package_naming(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            match = PACKAGE_PATTERN.search(line)
            if not match:
                continue
            package_name = match.group(1)
            if re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*", package_name):
                continue
            issues.append(
                Issue(
                    rule_id="SS501",
                    title="Kotlin package naming convention",
                    severity="low",
                    message="Use lower-case dot-separated package names (for example: com.company.feature).",
                    file_path=str(file_path),
                    line=idx,
                    column=match.start(1) + 1,
                )
            )
        return issues

    def _find_type_naming(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            match = TYPE_PATTERN.search(line)
            if not match:
                continue
            type_name = match.group(1)
            if _is_upper_camel_case(type_name):
                continue
            issues.append(
                Issue(
                    rule_id="SS502",
                    title="Kotlin type naming convention",
                    severity="medium",
                    message="Class/interface/object names should be UpperCamelCase.",
                    file_path=str(file_path),
                    line=idx,
                    column=match.start(1) + 1,
                )
            )
        return issues

    def _find_function_naming_and_params(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            match = FUNCTION_PATTERN.search(line)
            if not match:
                continue
            name = match.group(1)
            params_text = match.group(2).strip()
            if not _is_lower_camel_case(name):
                issues.append(
                    Issue(
                        rule_id="SS503",
                        title="Kotlin function naming convention",
                        severity="low",
                        message="Function names should be lowerCamelCase.",
                        file_path=str(file_path),
                        line=idx,
                        column=match.start(1) + 1,
                    )
                )

            params_count = 0 if not params_text else len([part for part in params_text.split(",") if part.strip()])
            if params_count > MAX_FUNCTION_PARAMS:
                issues.append(
                    Issue(
                        rule_id="SS504",
                        title="Kotlin function has too many parameters",
                        severity="medium",
                        message=f"Function has {params_count} parameters; target at most {MAX_FUNCTION_PARAMS}.",
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
            match = FUNCTION_PATTERN.search(line)
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
                        rule_id="SS505",
                        title="Kotlin function too long",
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
                rule_id="SS506",
                title="Kotlin nesting depth too high",
                severity="medium",
                message=f"Maximum block nesting depth is {max_depth}; keep it at or below {MAX_NESTING_DEPTH}.",
                file_path=str(file_path),
                line=1,
                column=1,
            )
        ]

    def _find_command_execution(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            if KOTLIN_COMMAND_EXEC_PATTERN.search(line) or KOTLIN_PROCESS_BUILDER_PATTERN.search(line):
                issues.append(
                    Issue(
                        rule_id="SS507",
                        title="Kotlin command execution usage",
                        severity="high",
                        message="Review OS command execution usage for command injection risks.",
                        file_path=str(file_path),
                        line=idx,
                        column=1,
                    )
                )
        return issues


def _is_upper_camel_case(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Z][A-Za-z0-9]*", name))


def _is_lower_camel_case(name: str) -> bool:
    return bool(re.fullmatch(r"[a-z][A-Za-z0-9]*", name))
