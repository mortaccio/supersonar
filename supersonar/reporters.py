from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

from supersonar.models import Issue, ScanResult
from supersonar.security import SECURITY_RULE_IDS


def _issue_to_dict(issue: Issue) -> dict[str, Any]:
    return {
        "rule_id": issue.rule_id,
        "title": issue.title,
        "severity": issue.severity,
        "message": issue.message,
        "file_path": issue.file_path,
        "line": issue.line,
        "column": issue.column,
    }


def to_json_report(result: ScanResult) -> dict[str, Any]:
    counts = Counter(issue.severity for issue in result.issues)
    rule_counts = Counter(issue.rule_id for issue in result.issues)
    files_with_issues = len({issue.file_path for issue in result.issues})
    security_issues = [issue for issue in result.issues if issue.rule_id in SECURITY_RULE_IDS]
    security_counts = Counter(issue.severity for issue in security_issues)
    security_rule_counts = Counter(issue.rule_id for issue in security_issues)
    security_file_counts = Counter(issue.file_path for issue in security_issues)
    security_lang_counts = Counter(_detect_language(issue.file_path) for issue in security_issues)
    payload = {
        "files_scanned": result.files_scanned,
        "files_with_issues": files_with_issues,
        "issues_total": len(result.issues),
        "severity_counts": {
            "low": counts.get("low", 0),
            "medium": counts.get("medium", 0),
            "high": counts.get("high", 0),
            "critical": counts.get("critical", 0),
        },
        "rule_counts": dict(sorted(rule_counts.items())),
        "security_summary": {
            "issues_total": len(security_issues),
            "files_with_issues": len(security_file_counts),
            "severity_counts": {
                "low": security_counts.get("low", 0),
                "medium": security_counts.get("medium", 0),
                "high": security_counts.get("high", 0),
                "critical": security_counts.get("critical", 0),
            },
            "rule_counts": dict(sorted(security_rule_counts.items())),
            "language_counts": dict(sorted(security_lang_counts.items())),
            "top_files": [
                {"file_path": path, "issues": issue_count}
                for path, issue_count in sorted(
                    security_file_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )[:10]
            ],
        },
        "issues": [_issue_to_dict(issue) for issue in result.issues],
    }
    if result.coverage is not None:
        payload["coverage"] = {
            "line_rate": result.coverage.line_rate,
            "line_percent": round(result.coverage.line_rate * 100.0, 2),
            "lines_covered": result.coverage.lines_covered,
            "lines_valid": result.coverage.lines_valid,
        }
    return payload


def to_sarif_report(result: ScanResult) -> dict[str, Any]:
    sarif_results: list[dict[str, Any]] = []
    for issue in result.issues:
        sarif_results.append(
            {
                "ruleId": issue.rule_id,
                "level": _severity_to_level(issue.severity),
                "message": {"text": f"{issue.title}: {issue.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": issue.file_path},
                            "region": {"startLine": issue.line, "startColumn": issue.column},
                        }
                    }
                ],
            }
        )

    run_payload: dict[str, Any] = {
        "tool": {"driver": {"name": "supersonar", "informationUri": "https://example.com"}},
        "results": sarif_results,
    }
    if result.coverage is not None:
        run_payload["properties"] = {"coverageLinePercent": round(result.coverage.line_rate * 100.0, 2)}

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run_payload],
    }


def write_report(payload: dict[str, Any], out: str | None) -> None:
    rendered = json.dumps(payload, indent=2)
    if out is None:
        print(rendered)
        return
    output_path = Path(out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")


def _severity_to_level(severity: str) -> str:
    mapping = {
        "low": "note",
        "medium": "warning",
        "high": "error",
        "critical": "error",
    }
    return mapping.get(severity, "warning")


def _detect_language(file_path: str) -> str:
    lower = file_path.lower()
    if lower.endswith(".py"):
        return "python"
    if lower.endswith(".java"):
        return "java"
    if lower.endswith(".kt"):
        return "kotlin"
    if lower.endswith(".go"):
        return "go"
    if lower.endswith((".js", ".jsx", ".ts", ".tsx")):
        return "javascript"
    if lower.endswith((".yaml", ".yml")):
        return "yaml"
    if lower.endswith(".dockerfile") or lower.endswith("/dockerfile") or lower == "dockerfile":
        return "dockerfile"
    return "other"
