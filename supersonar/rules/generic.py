from __future__ import annotations

from pathlib import Path
import re

from supersonar.models import Issue


SECRET_PATTERN = re.compile(
    r"(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(eval|Function)\s*\(", re.IGNORECASE)
TODO_FIXME_PATTERN = re.compile(r"\b(TODO|FIXME)\b", re.IGNORECASE)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


class GenericRuleEngine:
    def run(self, file_path: Path) -> list[Issue]:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        issues: list[Issue] = []
        issues.extend(self._find_todo_fixme(source, file_path))
        issues.extend(self._find_secrets(source, file_path))
        issues.extend(self._find_conflict_markers(source, file_path))
        issues.extend(self._find_dynamic_eval(source, file_path))
        issues.extend(self._find_private_keys(source, file_path))
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

    def _find_conflict_markers(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            if line.startswith("<<<<<<< ") or line.startswith("======= ") or line.startswith(">>>>>>> "):
                issues.append(
                    Issue(
                        rule_id="SS005",
                        title="Unresolved merge conflict marker",
                        severity="high",
                        message="Unresolved git merge marker found in source file.",
                        file_path=str(file_path),
                        line=idx,
                        column=1,
                    )
                )
        return issues

    def _find_dynamic_eval(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            if EVAL_PATTERN.search(line):
                issues.append(
                    Issue(
                        rule_id="SS101",
                        title="Dynamic code evaluation usage",
                        severity="critical",
                        message="Avoid dynamic evaluation patterns like eval()/Function().",
                        file_path=str(file_path),
                        line=idx,
                        column=1,
                    )
                )
        return issues

    def _find_private_keys(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            if PRIVATE_KEY_PATTERN.search(line):
                issues.append(
                    Issue(
                        rule_id="SS102",
                        title="Private key material in source",
                        severity="critical",
                        message="Private key block marker detected. Remove secrets from source control.",
                        file_path=str(file_path),
                        line=idx,
                        column=1,
                    )
                )
        return issues
