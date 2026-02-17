from __future__ import annotations

from pathlib import Path
import re
from itertools import combinations

from supersonar.models import Issue
from supersonar.rules.generic import GenericRuleEngine


PACKAGE_PATTERN = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)\s*;")
TYPE_PATTERN = re.compile(
    r"^\s*(?:public|protected|private|abstract|final|sealed|non-sealed|static|\s)*\s*"
    r"(class|interface|enum|record)\s+([A-Za-z_]\w*)\b"
)
METHOD_PATTERN = re.compile(
    r"^\s*(?:public|protected|private|static|final|abstract|synchronized|native|strictfp|\s)+"
    r"[\w<>\[\], ?]+?\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:\{|throws\b)"
)
CONSTANT_PATTERN = re.compile(r"\b(?:public\s+)?static\s+final\s+[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\b")
COMMAND_EXEC_PATTERN = re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(")
PROCESS_BUILDER_PATTERN = re.compile(r"\bnew\s+ProcessBuilder\s*\(")
MAX_METHOD_LINES = 60
MAX_METHOD_PARAMS = 6
MAX_NESTING_DEPTH = 4
MAX_IMPORT_FAN_OUT = 30
MAX_CLASS_METHODS = 20
MIN_COHESION_AVG = 0.15


class JavaRuleEngine:
    def __init__(self) -> None:
        self._generic_engine = GenericRuleEngine()

    def run(self, file_path: Path) -> list[Issue]:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        issues = self._generic_engine.run(file_path)
        issues.extend(self._find_package_naming(source, file_path))
        issues.extend(self._find_type_naming(source, file_path))
        issues.extend(self._find_method_naming(source, file_path))
        issues.extend(self._find_constant_naming(source, file_path))
        issues.extend(self._find_method_size_and_params(source, file_path))
        issues.extend(self._find_nesting_depth(source, file_path))
        issues.extend(self._find_command_execution(source, file_path))
        issues.extend(self._find_structural_quality_issues(source, file_path))
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
                    rule_id="SS201",
                    title="Java package naming convention",
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
        top_level_type: tuple[str, int, int] | None = None
        for idx, line in enumerate(source.splitlines(), start=1):
            match = TYPE_PATTERN.search(line)
            if not match:
                continue
            type_name = match.group(2)
            if not _is_upper_camel_case(type_name):
                issues.append(
                    Issue(
                        rule_id="SS202",
                        title="Java type naming convention",
                        severity="medium",
                        message="Class/interface/enum/record names should be UpperCamelCase.",
                        file_path=str(file_path),
                        line=idx,
                        column=match.start(2) + 1,
                    )
                )
            if top_level_type is None and " class " in f" {line} " and line.lstrip().startswith(("public ", "class ")):
                top_level_type = (type_name, idx, match.start(2) + 1)

        if top_level_type is not None:
            type_name, idx, col = top_level_type
            file_stem = file_path.stem
            if type_name != file_stem:
                issues.append(
                    Issue(
                        rule_id="SS203",
                        title="Java class/file naming mismatch",
                        severity="medium",
                        message=f"Top-level public class '{type_name}' should be declared in '{type_name}.java'.",
                        file_path=str(file_path),
                        line=idx,
                        column=col,
                    )
                )
        return issues

    def _find_method_naming(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            match = METHOD_PATTERN.search(line)
            if not match:
                continue
            method_name = match.group(1)
            if method_name in {"if", "for", "while", "switch", "catch", "return"}:
                continue
            if _is_constructor_name(method_name, file_path):
                continue
            if _is_lower_camel_case(method_name):
                continue
            issues.append(
                Issue(
                    rule_id="SS204",
                    title="Java method naming convention",
                    severity="low",
                    message="Method names should be lowerCamelCase.",
                    file_path=str(file_path),
                    line=idx,
                    column=match.start(1) + 1,
                )
            )
        return issues

    def _find_constant_naming(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            match = CONSTANT_PATTERN.search(line)
            if not match:
                continue
            const_name = match.group(1)
            if re.fullmatch(r"[A-Z][A-Z0-9_]*", const_name):
                continue
            issues.append(
                Issue(
                    rule_id="SS205",
                    title="Java constant naming convention",
                    severity="low",
                    message="static final constants should use UPPER_SNAKE_CASE.",
                    file_path=str(file_path),
                    line=idx,
                    column=match.start(1) + 1,
                )
            )
        return issues

    def _find_method_size_and_params(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        lines = source.splitlines()
        idx = 0
        while idx < len(lines):
            line = lines[idx]
            match = METHOD_PATTERN.search(line)
            if not match:
                idx += 1
                continue

            method_name = match.group(1)
            params_match = re.search(r"\(([^)]*)\)", line)
            if params_match:
                params_text = params_match.group(1).strip()
                params_count = 0 if not params_text else len([part for part in params_text.split(",") if part.strip()])
                if params_count > MAX_METHOD_PARAMS:
                    issues.append(
                        Issue(
                            rule_id="SS206",
                            title="Java method has too many parameters",
                            severity="medium",
                            message=f"Method has {params_count} parameters; target at most {MAX_METHOD_PARAMS}.",
                            file_path=str(file_path),
                            line=idx + 1,
                            column=match.start(1) + 1,
                        )
                    )

            brace_index = line.find("{")
            if brace_index < 0:
                idx += 1
                continue

            open_count = line.count("{")
            close_count = line.count("}")
            brace_depth = open_count - close_count
            end_idx = idx
            while brace_depth > 0 and end_idx + 1 < len(lines):
                end_idx += 1
                brace_depth += lines[end_idx].count("{")
                brace_depth -= lines[end_idx].count("}")

            method_lines = end_idx - idx + 1
            if method_lines > MAX_METHOD_LINES and method_name != file_path.stem:
                issues.append(
                    Issue(
                        rule_id="SS207",
                        title="Java method too long",
                        severity="medium",
                        message=f"Method spans {method_lines} lines; target at most {MAX_METHOD_LINES}.",
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
                rule_id="SS208",
                title="Java nesting depth too high",
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
            if COMMAND_EXEC_PATTERN.search(line) or PROCESS_BUILDER_PATTERN.search(line):
                issues.append(
                    Issue(
                        rule_id="SS221",
                        title="Java command execution usage",
                        severity="high",
                        message="Review OS command execution (Runtime.exec/ProcessBuilder) for injection risks.",
                        file_path=str(file_path),
                        line=idx,
                        column=1,
                    )
                )
        return issues

    def _find_structural_quality_issues(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []

        import_fan_out = _java_import_fan_out(source)
        if import_fan_out > MAX_IMPORT_FAN_OUT:
            issues.append(
                Issue(
                    rule_id="SS219",
                    title="High import fan-out",
                    severity="medium",
                    message=f"File imports {import_fan_out} dependencies; consider reducing coupling.",
                    file_path=str(file_path),
                    line=1,
                    column=1,
                )
            )

        lines = source.splitlines()
        for class_name, class_line, start_idx, end_idx in _java_class_ranges(lines):
            class_lines = lines[start_idx : end_idx + 1]
            methods = _java_method_ranges(class_lines, start_idx)
            if len(methods) > MAX_CLASS_METHODS:
                issues.append(
                    Issue(
                        rule_id="SS209",
                        title="Class has too many methods",
                        severity="medium",
                        message=(
                            f"Class '{class_name}' declares {len(methods)} methods; "
                            f"target at most {MAX_CLASS_METHODS}."
                        ),
                        file_path=str(file_path),
                        line=class_line,
                        column=1,
                    )
                )

            cohesion = _java_class_cohesion(lines, methods)
            if cohesion is not None and cohesion < MIN_COHESION_AVG:
                issues.append(
                    Issue(
                        rule_id="SS220",
                        title="Low class cohesion",
                        severity="medium",
                        message=(
                            f"Class '{class_name}' methods share little common state "
                            f"(cohesion score {cohesion:.2f})."
                        ),
                        file_path=str(file_path),
                        line=class_line,
                        column=1,
                    )
                )

        return issues


def _is_upper_camel_case(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Z][A-Za-z0-9]*", name))


def _is_lower_camel_case(name: str) -> bool:
    return bool(re.fullmatch(r"[a-z][A-Za-z0-9]*", name))


def _is_constructor_name(method_name: str, file_path: Path) -> bool:
    return method_name == file_path.stem


def _java_import_fan_out(source: str) -> int:
    imports: set[str] = set()
    for line in source.splitlines():
        match = re.match(r"^\s*import\s+([A-Za-z0-9_.*]+)\s*;", line)
        if not match:
            continue
        imports.add(match.group(1))
    return len(imports)


def _java_class_ranges(lines: list[str]) -> list[tuple[str, int, int, int]]:
    results: list[tuple[str, int, int, int]] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        match = TYPE_PATTERN.search(line)
        if not match or match.group(1) != "class":
            idx += 1
            continue

        class_name = match.group(2)
        start_idx = idx
        open_idx = idx
        while open_idx < len(lines) and "{" not in lines[open_idx]:
            open_idx += 1
        if open_idx >= len(lines):
            break

        depth = 0
        end_idx = open_idx
        while end_idx < len(lines):
            depth += lines[end_idx].count("{")
            depth -= lines[end_idx].count("}")
            if depth <= 0:
                break
            end_idx += 1

        results.append((class_name, idx + 1, start_idx, min(end_idx, len(lines) - 1)))
        idx = end_idx + 1
    return results


def _java_method_ranges(class_lines: list[str], offset: int) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    idx = 0
    while idx < len(class_lines):
        line = class_lines[idx]
        match = METHOD_PATTERN.search(line)
        if not match:
            idx += 1
            continue
        if "{" not in line:
            idx += 1
            continue
        depth = line.count("{") - line.count("}")
        end_idx = idx
        while depth > 0 and end_idx + 1 < len(class_lines):
            end_idx += 1
            depth += class_lines[end_idx].count("{")
            depth -= class_lines[end_idx].count("}")
        ranges.append((offset + idx, offset + end_idx))
        idx = end_idx + 1
    return ranges


def _java_class_cohesion(lines: list[str], methods: list[tuple[int, int]]) -> float | None:
    field_sets: list[set[str]] = []
    for start, end in methods:
        body = "\n".join(lines[start : end + 1])
        fields = set(re.findall(r"\bthis\.([A-Za-z_]\w*)\b", body))
        if fields:
            field_sets.append(fields)

    if len(field_sets) < 3:
        return None

    scores: list[float] = []
    for left, right in combinations(field_sets, 2):
        union = left | right
        if not union:
            continue
        scores.append(len(left & right) / len(union))

    if not scores:
        return None
    return sum(scores) / len(scores)
