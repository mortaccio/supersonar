from __future__ import annotations

import ast
from pathlib import Path
import re

from supersonar.models import Issue


SECRET_PATTERN = re.compile(
    r"(api[_-]?key|secret|token|password)\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
TODO_FIXME_PATTERN = re.compile(r"\b(TODO|FIXME)\b", re.IGNORECASE)


class PythonRuleEngine:
    def run(self, file_path: Path) -> list[Issue]:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        issues: list[Issue] = []
        issues.extend(self._find_todo_fixme(source, file_path))
        issues.extend(self._find_secrets(source, file_path))
        issues.extend(self._analyze_ast(source, file_path))
        return issues

    def _find_todo_fixme(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            match = TODO_FIXME_PATTERN.search(line)
            if match:
                issues.append(
                    Issue(
                        rule_id="SS004",
                        title="Work item marker in source",
                        severity="low",
                        message="Found TODO/FIXME marker. Track and resolve before release.",
                        file_path=str(file_path),
                        line=idx,
                        column=match.start() + 1,
                    )
                )
        return issues

    def _find_secrets(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            if SECRET_PATTERN.search(line):
                issues.append(
                    Issue(
                        rule_id="SS003",
                        title="Potential hardcoded secret",
                        severity="high",
                        message="Potential credential/token assignment found in source.",
                        file_path=str(file_path),
                        line=idx,
                        column=1,
                    )
                )
        return issues

    def _analyze_ast(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            issues.append(
                Issue(
                    rule_id="SS000",
                    title="Syntax error",
                    severity="medium",
                    message=f"Could not parse file: {exc.msg}",
                    file_path=str(file_path),
                    line=exc.lineno or 1,
                    column=exc.offset or 1,
                )
            )
            return issues

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"eval", "exec"}:
                    issues.append(
                        Issue(
                            rule_id="SS001",
                            title="Dangerous dynamic execution",
                            severity="critical",
                            message=f"Avoid {node.func.id}() because it executes dynamic code.",
                            file_path=str(file_path),
                            line=getattr(node, "lineno", 1),
                            column=getattr(node, "col_offset", 0) + 1,
                        )
                    )
            if isinstance(node, ast.ExceptHandler):
                is_bare = node.type is None
                is_broad = _is_broad_except_type(node.type)
                if is_bare or is_broad:
                    issues.append(
                        Issue(
                            rule_id="SS002",
                            title="Broad exception handling",
                            severity="medium",
                            message="Avoid bare except or except Exception; catch specific errors.",
                            file_path=str(file_path),
                            line=getattr(node, "lineno", 1),
                            column=getattr(node, "col_offset", 0) + 1,
                        )
                    )
            if isinstance(node, ast.Call) and _is_subprocess_shell_true_call(node):
                issues.append(
                    Issue(
                        rule_id="SS006",
                        title="Shell execution with shell=True",
                        severity="high",
                        message="Avoid subprocess calls with shell=True; pass argument arrays instead.",
                        file_path=str(file_path),
                        line=getattr(node, "lineno", 1),
                        column=getattr(node, "col_offset", 0) + 1,
                    )
                )
            if isinstance(node, ast.Call) and _is_unsafe_yaml_load(node):
                issues.append(
                    Issue(
                        rule_id="SS007",
                        title="Unsafe YAML deserialization",
                        severity="high",
                        message="Use yaml.safe_load() or pass Loader=yaml.SafeLoader to yaml.load().",
                        file_path=str(file_path),
                        line=getattr(node, "lineno", 1),
                        column=getattr(node, "col_offset", 0) + 1,
                    )
                )
        return issues


def _is_subprocess_shell_true_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if not isinstance(node.func.value, ast.Name):
        return False
    if node.func.value.id != "subprocess":
        return False
    if node.func.attr not in {"run", "Popen", "call", "check_call", "check_output"}:
        return False
    for keyword in node.keywords:
        if keyword.arg != "shell":
            continue
        return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
    return False


def _is_unsafe_yaml_load(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if not isinstance(node.func.value, ast.Name):
        return False
    if node.func.value.id != "yaml" or node.func.attr != "load":
        return False

    for keyword in node.keywords:
        if keyword.arg != "Loader":
            continue
        if isinstance(keyword.value, ast.Attribute) and isinstance(keyword.value.value, ast.Name):
            if keyword.value.value.id == "yaml" and keyword.value.attr == "SafeLoader":
                return False
        return True

    return True


def _is_broad_except_type(node: ast.expr | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in {"Exception", "BaseException"}
    if isinstance(node, ast.Tuple):
        return any(_is_broad_except_type(elt) for elt in node.elts)
    return False
