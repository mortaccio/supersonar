from __future__ import annotations

import ast
from itertools import combinations
from pathlib import Path
import re

from supersonar.models import Issue


SECRET_PATTERN = re.compile(
    r"(api[_-]?key|secret|token|password)\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
TODO_FIXME_PATTERN = re.compile(r"\b(TODO|FIXME)\b", re.IGNORECASE)
SNAKE_CASE_PATTERN = re.compile(r"^[a-z_][a-z0-9_]*$")
UPPER_CAMEL_CASE_PATTERN = re.compile(r"^[A-Z][A-Za-z0-9]*$")
MAX_FUNCTION_LINES = 60
MAX_FUNCTION_ARGS = 6
MAX_NESTING_DEPTH = 4
MAX_IMPORT_FAN_OUT = 20
MAX_CLASS_METHODS = 15
MAX_MODULE_FUNCTIONS = 20
MIN_COHESION_AVG = 0.15


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
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                issues.extend(self._find_function_quality_issues(node, file_path))
            if isinstance(node, ast.ClassDef) and not UPPER_CAMEL_CASE_PATTERN.fullmatch(node.name):
                issues.append(
                    Issue(
                        rule_id="SS214",
                        title="Python class naming convention",
                        severity="low",
                        message="Class names should be UpperCamelCase.",
                        file_path=str(file_path),
                        line=node.lineno,
                        column=node.col_offset + 1,
                    )
                )

        depth = _max_python_nesting(tree)
        if depth > MAX_NESTING_DEPTH:
            issues.append(
                Issue(
                    rule_id="SS212",
                    title="Excessive nesting depth",
                    severity="medium",
                    message=f"Maximum nesting depth is {depth}; keep it at or below {MAX_NESTING_DEPTH}.",
                    file_path=str(file_path),
                    line=1,
                    column=1,
                )
            )
        issues.extend(self._find_structural_quality_issues(tree, file_path))
        return issues

    def _find_function_quality_issues(self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []

        if not _is_allowed_function_name(node.name):
            issues.append(
                Issue(
                    rule_id="SS213",
                    title="Python function naming convention",
                    severity="low",
                    message="Function names should be snake_case.",
                    file_path=str(file_path),
                    line=node.lineno,
                    column=node.col_offset + 1,
                )
            )

        if hasattr(node, "end_lineno") and node.end_lineno is not None:
            function_lines = node.end_lineno - node.lineno + 1
            if function_lines > MAX_FUNCTION_LINES:
                issues.append(
                    Issue(
                        rule_id="SS210",
                        title="Function too long",
                        severity="medium",
                        message=f"Function spans {function_lines} lines; target at most {MAX_FUNCTION_LINES}.",
                        file_path=str(file_path),
                        line=node.lineno,
                        column=node.col_offset + 1,
                    )
                )

        positional_args = len(node.args.args)
        keyword_only_args = len(node.args.kwonlyargs)
        total_args = positional_args + keyword_only_args
        if node.args.vararg is not None:
            total_args += 1
        if node.args.kwarg is not None:
            total_args += 1
        if total_args > MAX_FUNCTION_ARGS:
            issues.append(
                Issue(
                    rule_id="SS211",
                    title="Too many function parameters",
                    severity="medium",
                    message=f"Function has {total_args} parameters; target at most {MAX_FUNCTION_ARGS}.",
                    file_path=str(file_path),
                    line=node.lineno,
                    column=node.col_offset + 1,
                )
            )

        return issues

    def _find_structural_quality_issues(self, tree: ast.Module, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []

        fan_out = _python_import_fan_out(tree)
        if fan_out > MAX_IMPORT_FAN_OUT:
            issues.append(
                Issue(
                    rule_id="SS215",
                    title="High import fan-out",
                    severity="medium",
                    message=f"Module imports {fan_out} dependencies; consider reducing coupling.",
                    file_path=str(file_path),
                    line=1,
                    column=1,
                )
            )

        top_level_functions = sum(1 for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
        if top_level_functions > MAX_MODULE_FUNCTIONS:
            issues.append(
                Issue(
                    rule_id="SS217",
                    title="Large module surface",
                    severity="low",
                    message=(
                        f"Module defines {top_level_functions} top-level functions; consider splitting by responsibility."
                    ),
                    file_path=str(file_path),
                    line=1,
                    column=1,
                )
            )

        class_nodes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
        for class_node in class_nodes:
            methods = [
                node
                for node in class_node.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("__")
            ]
            if len(methods) > MAX_CLASS_METHODS:
                issues.append(
                    Issue(
                        rule_id="SS216",
                        title="Class has too many methods",
                        severity="medium",
                        message=(
                            f"Class '{class_node.name}' declares {len(methods)} methods; "
                            f"target at most {MAX_CLASS_METHODS}."
                        ),
                        file_path=str(file_path),
                        line=class_node.lineno,
                        column=class_node.col_offset + 1,
                    )
                )

            cohesion = _python_class_cohesion(methods)
            if cohesion is not None and cohesion < MIN_COHESION_AVG:
                issues.append(
                    Issue(
                        rule_id="SS218",
                        title="Low class cohesion",
                        severity="medium",
                        message=(
                            f"Class '{class_node.name}' methods share little common state "
                            f"(cohesion score {cohesion:.2f})."
                        ),
                        file_path=str(file_path),
                        line=class_node.lineno,
                        column=class_node.col_offset + 1,
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


def _is_allowed_function_name(name: str) -> bool:
    if name.startswith("__") and name.endswith("__"):
        return True
    return bool(SNAKE_CASE_PATTERN.fullmatch(name))


def _max_python_nesting(tree: ast.AST) -> int:
    nesting_nodes = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match)

    def walk(node: ast.AST, depth: int) -> int:
        next_depth = depth + 1 if isinstance(node, nesting_nodes) else depth
        max_depth = next_depth
        for child in ast.iter_child_nodes(node):
            max_depth = max(max_depth, walk(child, next_depth))
        return max_depth

    return walk(tree, 0)


def _python_import_fan_out(tree: ast.Module) -> int:
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    return len(imports)


def _python_class_cohesion(methods: list[ast.FunctionDef | ast.AsyncFunctionDef]) -> float | None:
    field_sets = [_self_fields_in_method(method) for method in methods]
    useful = [fields for fields in field_sets if fields]
    if len(useful) < 3:
        return None

    scores: list[float] = []
    for left, right in combinations(useful, 2):
        union = left | right
        if not union:
            continue
        scores.append(len(left & right) / len(union))

    if not scores:
        return None
    return sum(scores) / len(scores)


def _self_fields_in_method(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    fields: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Attribute):
            continue
        if not isinstance(child.value, ast.Name):
            continue
        if child.value.id != "self":
            continue
        fields.add(child.attr)
    return fields
