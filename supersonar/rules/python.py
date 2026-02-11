from __future__ import annotations

import ast
from pathlib import Path
import re

from supersonar.models import Issue


SECRET_PATTERN = re.compile(
    r"(api[_-]?key|secret|token|password)\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)


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
            if "TODO" in line or "FIXME" in line:
                issues.append(
                    Issue(
                        rule_id="SS004",
                        title="Work item marker in source",
                        severity="low",
                        message="Found TODO/FIXME marker. Track and resolve before release.",
                        file_path=str(file_path),
                        line=idx,
                        column=max(line.find("TODO"), line.find("FIXME"), 0) + 1,
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
                is_exception = isinstance(node.type, ast.Name) and node.type.id == "Exception"
                if is_bare or is_exception:
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
        return issues

