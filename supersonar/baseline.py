from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from supersonar.models import Issue, ScanResult


def load_baseline_fingerprints(path: str) -> set[tuple[str, str, int, int, str]]:
    payload = _read_json(path)
    issues = payload.get("issues")
    if not isinstance(issues, list):
        raise ValueError("Baseline report must contain an 'issues' array.")

    fingerprints: set[tuple[str, str, int, int, str]] = set()
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        rule_id = issue.get("rule_id")
        file_path = issue.get("file_path")
        line = issue.get("line")
        column = issue.get("column")
        message = issue.get("message")
        if not isinstance(rule_id, str) or not isinstance(file_path, str) or not isinstance(message, str):
            continue
        if not isinstance(line, int) or not isinstance(column, int):
            continue
        fingerprints.add((file_path, rule_id, line, column, message))
    return fingerprints


def filter_new_issues(
    result: ScanResult, baseline_fingerprints: set[tuple[str, str, int, int, str]]
) -> tuple[ScanResult, int]:
    new_issues: list[Issue] = []
    for issue in result.issues:
        fingerprint = (issue.file_path, issue.rule_id, issue.line, issue.column, issue.message)
        if fingerprint not in baseline_fingerprints:
            new_issues.append(issue)
    baseline_matched = len(result.issues) - len(new_issues)
    return (
        ScanResult(issues=new_issues, files_scanned=result.files_scanned, coverage=result.coverage),
        baseline_matched,
    )


def _read_json(path: str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Baseline report must be a JSON object.")
    return payload
