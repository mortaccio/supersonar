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
MAX_LINE_LENGTH = 140
MAX_FILE_LINES = 800
DUPLICATE_BLOCK_WINDOW = 4
MAX_DUPLICATE_FINDINGS_PER_FILE = 20


class GenericRuleEngine:
    def run(self, file_path: Path) -> list[Issue]:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        issues: list[Issue] = []
        issues.extend(self._find_todo_fixme(source, file_path))
        issues.extend(self._find_secrets(source, file_path))
        issues.extend(self._find_conflict_markers(source, file_path))
        issues.extend(self._find_dynamic_eval(source, file_path))
        issues.extend(self._find_private_keys(source, file_path))
        issues.extend(self._find_long_lines(source, file_path))
        issues.extend(self._find_trailing_whitespace(source, file_path))
        issues.extend(self._find_large_file(source, file_path))
        issues.extend(self._find_duplicate_blocks(source, file_path))
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

    def _find_long_lines(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            if len(line) <= MAX_LINE_LENGTH:
                continue
            issues.append(
                Issue(
                    rule_id="SS103",
                    title="Excessive line length",
                    severity="low",
                    message=f"Line length exceeds {MAX_LINE_LENGTH} characters; wrap for readability.",
                    file_path=str(file_path),
                    line=idx,
                    column=MAX_LINE_LENGTH + 1,
                )
            )
        return issues

    def _find_trailing_whitespace(self, source: str, file_path: Path) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(source.splitlines(), start=1):
            stripped = line.rstrip("\r\n")
            if stripped == stripped.rstrip(" \t"):
                continue
            issues.append(
                Issue(
                    rule_id="SS104",
                    title="Trailing whitespace",
                    severity="low",
                    message="Trailing whitespace reduces readability and creates noisy diffs.",
                    file_path=str(file_path),
                    line=idx,
                    column=len(stripped.rstrip(" \t")) + 1,
                )
            )
        return issues

    def _find_large_file(self, source: str, file_path: Path) -> list[Issue]:
        line_count = len(source.splitlines())
        if line_count <= MAX_FILE_LINES:
            return []
        return [
            Issue(
                rule_id="SS106",
                title="Large source file",
                severity="medium",
                message=f"File has {line_count} lines; consider splitting responsibilities into smaller units.",
                file_path=str(file_path),
                line=1,
                column=1,
            )
        ]

    def _find_duplicate_blocks(self, source: str, file_path: Path) -> list[Issue]:
        lines = source.splitlines()
        if len(lines) < DUPLICATE_BLOCK_WINDOW * 2:
            return []

        normalized = [re.sub(r"\s+", " ", line).strip() for line in lines]
        windows: dict[str, list[int]] = {}
        for idx in range(len(normalized) - DUPLICATE_BLOCK_WINDOW + 1):
            chunk = normalized[idx : idx + DUPLICATE_BLOCK_WINDOW]
            if any(not part for part in chunk):
                continue
            if sum(len(part) for part in chunk) < 80:
                continue
            key = "\n".join(chunk)
            windows.setdefault(key, []).append(idx + 1)

        issues: list[Issue] = []
        for occurrences in windows.values():
            if len(occurrences) < 2:
                continue
            for line_number in occurrences[1:]:
                issues.append(
                    Issue(
                        rule_id="SS105",
                        title="Duplicated code block",
                        severity="medium",
                        message=(
                            f"Repeated {DUPLICATE_BLOCK_WINDOW}-line block detected "
                            f"(first seen near line {occurrences[0]})."
                        ),
                        file_path=str(file_path),
                        line=line_number,
                        column=1,
                    )
                )
                if len(issues) >= MAX_DUPLICATE_FINDINGS_PER_FILE:
                    return issues
        return issues
