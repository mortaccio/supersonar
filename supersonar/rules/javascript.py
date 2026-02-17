from __future__ import annotations

from pathlib import Path
import re

from supersonar.models import Issue
from supersonar.rules.generic import GenericRuleEngine


FUNCTION_DECL_PATTERN = re.compile(r"^\s*function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
ARROW_DECL_PATTERN = re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*\(([^)]*)\)\s*=>")
CLASS_COMPONENT_PATTERN = re.compile(r"^\s*class\s+([A-Za-z_]\w*)\s+extends\s+(?:React\.)?Component\b")
JSX_TAG_PATTERN = re.compile(r"<[A-Za-z][A-Za-z0-9]*")
CHILD_PROCESS_REQUIRE_DESTRUCTURED_PATTERN = re.compile(
    r"\b(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*require\(\s*['\"]child_process['\"]\s*\)"
)
CHILD_PROCESS_REQUIRE_NAMESPACE_PATTERN = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*require\(\s*['\"]child_process['\"]\s*\)"
)
CHILD_PROCESS_IMPORT_DESTRUCTURED_PATTERN = re.compile(
    r"^\s*import\s*\{\s*([^}]+)\}\s*from\s*['\"]child_process['\"]"
)
CHILD_PROCESS_IMPORT_NAMESPACE_PATTERN = re.compile(
    r"^\s*import\s+\*\s+as\s+([A-Za-z_]\w*)\s+from\s+['\"]child_process['\"]"
)
CHILD_PROCESS_IMPORT_DEFAULT_PATTERN = re.compile(
    r"^\s*import\s+([A-Za-z_]\w*)\s+from\s+['\"]child_process['\"]"
)
CHILD_PROCESS_INLINE_EXEC_PATTERN = re.compile(
    r"require\(\s*['\"]child_process['\"]\s*\)\s*\.\s*exec(?:Sync)?\s*\("
)
MAX_FUNCTION_PARAMS = 6
MAX_FUNCTION_LINES = 60
MAX_NESTING_DEPTH = 4


class JavaScriptRuleEngine:
    def __init__(self) -> None:
        self._generic_engine = GenericRuleEngine()

    def run(self, file_path: Path) -> list[Issue]:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        issues = self._generic_engine.run(file_path)
        issues.extend(self._find_naming_issues(source, file_path))
        issues.extend(self._find_function_size_and_params(source, file_path))
        issues.extend(self._find_nesting_depth(source, file_path))
        issues.extend(self._find_command_execution(source, file_path))
        return issues

    def _find_naming_issues(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        lines = source.splitlines()
        for idx, line in enumerate(lines, start=1):
            function_match = FUNCTION_DECL_PATTERN.search(line)
            arrow_match = ARROW_DECL_PATTERN.search(line)
            class_match = CLASS_COMPONENT_PATTERN.search(line)

            if function_match:
                name = function_match.group(1)
                params = function_match.group(2)
                is_component = _looks_like_react_component(name, line, lines, idx - 1)
                if is_component and not _is_upper_camel_case(name):
                    issues.append(
                        Issue(
                            rule_id="SS302",
                            title="React component naming convention",
                            severity="low",
                            message="React component names should be UpperCamelCase.",
                            file_path=str(file_path),
                            line=idx,
                            column=function_match.start(1) + 1,
                        )
                    )
                elif not is_component and not _is_lower_camel_case(name):
                    issues.append(
                        Issue(
                            rule_id="SS301",
                            title="JavaScript function naming convention",
                            severity="low",
                            message="Function names should be lowerCamelCase.",
                            file_path=str(file_path),
                            line=idx,
                            column=function_match.start(1) + 1,
                        )
                    )
                issues.extend(self._param_issue_if_needed(len(_split_params(params)), file_path, idx, function_match.start(1) + 1))

            if arrow_match:
                name = arrow_match.group(1)
                params = arrow_match.group(2)
                is_component = _looks_like_react_component(name, line, lines, idx - 1)
                if is_component and not _is_upper_camel_case(name):
                    issues.append(
                        Issue(
                            rule_id="SS302",
                            title="React component naming convention",
                            severity="low",
                            message="React component names should be UpperCamelCase.",
                            file_path=str(file_path),
                            line=idx,
                            column=arrow_match.start(1) + 1,
                        )
                    )
                elif not is_component and not _is_lower_camel_case(name):
                    issues.append(
                        Issue(
                            rule_id="SS301",
                            title="JavaScript function naming convention",
                            severity="low",
                            message="Function names should be lowerCamelCase.",
                            file_path=str(file_path),
                            line=idx,
                            column=arrow_match.start(1) + 1,
                        )
                    )
                issues.extend(self._param_issue_if_needed(len(_split_params(params)), file_path, idx, arrow_match.start(1) + 1))

            if class_match:
                class_name = class_match.group(1)
                if not _is_upper_camel_case(class_name):
                    issues.append(
                        Issue(
                            rule_id="SS302",
                            title="React component naming convention",
                            severity="low",
                            message="React component names should be UpperCamelCase.",
                            file_path=str(file_path),
                            line=idx,
                            column=class_match.start(1) + 1,
                        )
                    )
        return issues

    def _param_issue_if_needed(self, params_count: int, file_path: Path, line: int, column: int) -> list[Issue]:
        if params_count <= MAX_FUNCTION_PARAMS:
            return []
        return [
            Issue(
                rule_id="SS303",
                title="JavaScript function has too many parameters",
                severity="medium",
                message=f"Function has {params_count} parameters; target at most {MAX_FUNCTION_PARAMS}.",
                file_path=str(file_path),
                line=line,
                column=column,
            )
        ]

    def _find_function_size_and_params(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        lines = source.splitlines()
        idx = 0
        while idx < len(lines):
            line = lines[idx]
            fn_match = FUNCTION_DECL_PATTERN.search(line) or ARROW_DECL_PATTERN.search(line)
            if not fn_match or "{" not in line:
                idx += 1
                continue
            open_depth = line.count("{") - line.count("}")
            end_idx = idx
            while open_depth > 0 and end_idx + 1 < len(lines):
                end_idx += 1
                open_depth += lines[end_idx].count("{")
                open_depth -= lines[end_idx].count("}")
            fn_lines = end_idx - idx + 1
            if fn_lines > MAX_FUNCTION_LINES:
                issues.append(
                    Issue(
                        rule_id="SS304",
                        title="JavaScript function too long",
                        severity="medium",
                        message=f"Function spans {fn_lines} lines; target at most {MAX_FUNCTION_LINES}.",
                        file_path=str(file_path),
                        line=idx + 1,
                        column=fn_match.start(1) + 1,
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
                rule_id="SS305",
                title="JavaScript nesting depth too high",
                severity="medium",
                message=f"Maximum block nesting depth is {max_depth}; keep it at or below {MAX_NESTING_DEPTH}.",
                file_path=str(file_path),
                line=1,
                column=1,
            )
        ]

    def _find_command_execution(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        direct_exec_names: set[str] = set()
        namespace_exec_names: set[str] = {"child_process"}

        for idx, line in enumerate(source.splitlines(), start=1):
            code = _strip_js_line_comment(line).strip()
            if not code:
                continue

            destructured_require_match = CHILD_PROCESS_REQUIRE_DESTRUCTURED_PATTERN.search(code)
            if destructured_require_match:
                direct_exec_names.update(_extract_child_process_exec_aliases(destructured_require_match.group(1), js_import=False))
                continue

            namespace_require_match = CHILD_PROCESS_REQUIRE_NAMESPACE_PATTERN.search(code)
            if namespace_require_match:
                namespace_exec_names.add(namespace_require_match.group(1))
                continue

            destructured_import_match = CHILD_PROCESS_IMPORT_DESTRUCTURED_PATTERN.search(code)
            if destructured_import_match:
                direct_exec_names.update(_extract_child_process_exec_aliases(destructured_import_match.group(1), js_import=True))
                continue

            namespace_import_match = CHILD_PROCESS_IMPORT_NAMESPACE_PATTERN.search(code)
            if namespace_import_match:
                namespace_exec_names.add(namespace_import_match.group(1))
                continue

            default_import_match = CHILD_PROCESS_IMPORT_DEFAULT_PATTERN.search(code)
            if default_import_match:
                namespace_exec_names.add(default_import_match.group(1))
                continue

            if CHILD_PROCESS_INLINE_EXEC_PATTERN.search(code):
                issues.append(
                    Issue(
                        rule_id="SS306",
                        title="Node.js command execution usage",
                        severity="high",
                        message="Review child_process exec/execSync usage for command injection risks.",
                        file_path=str(file_path),
                        line=idx,
                        column=1,
                    )
                )
                continue

            if any(re.search(rf"\b{re.escape(name)}\s*\(", code) for name in direct_exec_names):
                issues.append(
                    Issue(
                        rule_id="SS306",
                        title="Node.js command execution usage",
                        severity="high",
                        message="Review child_process exec/execSync usage for command injection risks.",
                        file_path=str(file_path),
                        line=idx,
                        column=1,
                    )
                )
                continue

            if any(re.search(rf"\b{re.escape(name)}\s*\.\s*exec(?:Sync)?\s*\(", code) for name in namespace_exec_names):
                issues.append(
                    Issue(
                        rule_id="SS306",
                        title="Node.js command execution usage",
                        severity="high",
                        message="Review child_process exec/execSync usage for command injection risks.",
                        file_path=str(file_path),
                        line=idx,
                        column=1,
                    )
                )
        return issues


def _split_params(params: str) -> list[str]:
    text = params.strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def _extract_child_process_exec_aliases(spec: str, js_import: bool) -> set[str]:
    names: set[str] = set()
    for raw in spec.split(","):
        token = raw.strip()
        if not token:
            continue
        if js_import and " as " in token:
            left, right = token.split(" as ", 1)
            source, alias = left.strip(), right.strip()
        elif not js_import and ":" in token:
            left, right = token.split(":", 1)
            source, alias = left.strip(), right.strip()
        else:
            source, alias = token, token
        if source in {"exec", "execSync"} and alias:
            names.add(alias)
    return names


def _strip_js_line_comment(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith("//"):
        return ""
    idx = line.find("//")
    if idx < 0:
        return line
    return line[:idx]


def _looks_like_react_component(name: str, line: str, lines: list[str], line_idx: int) -> bool:
    if not _is_upper_camel_case(name):
        candidate = False
    else:
        candidate = True
    if "React" in line or "jsx" in line.lower():
        candidate = True
    window = "\n".join(lines[line_idx : min(len(lines), line_idx + 8)])
    if JSX_TAG_PATTERN.search(window):
        candidate = True
    return candidate


def _is_upper_camel_case(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Z][A-Za-z0-9]*", name))


def _is_lower_camel_case(name: str) -> bool:
    return bool(re.fullmatch(r"[a-z][A-Za-z0-9]*", name))
