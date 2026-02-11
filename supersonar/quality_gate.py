from __future__ import annotations

from collections import Counter

from supersonar.models import ScanResult, Severity


SEVERITY_ORDER: dict[Severity, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def evaluate_gate(
    result: ScanResult,
    fail_on: Severity | None = None,
    max_issues: int | None = None,
    max_low: int | None = None,
    max_medium: int | None = None,
    max_high: int | None = None,
    max_critical: int | None = None,
    min_coverage: float | None = None,
) -> tuple[bool, list[str]]:
    failed_reasons: list[str] = []
    severity_counts = Counter(issue.severity for issue in result.issues)

    if fail_on is not None:
        threshold = SEVERITY_ORDER[fail_on]
        if any(SEVERITY_ORDER[issue.severity] >= threshold for issue in result.issues):
            failed_reasons.append(f"Detected issue severity >= '{fail_on}'")

    if max_issues is not None and len(result.issues) > max_issues:
        failed_reasons.append(f"Issue count {len(result.issues)} exceeds max_issues={max_issues}")

    per_severity_limits: dict[Severity, int | None] = {
        "low": max_low,
        "medium": max_medium,
        "high": max_high,
        "critical": max_critical,
    }
    for severity, limit in per_severity_limits.items():
        if limit is not None and severity_counts.get(severity, 0) > limit:
            failed_reasons.append(
                f"{severity} issue count {severity_counts[severity]} exceeds max_{severity}={limit}"
            )

    if min_coverage is not None:
        if result.coverage is None:
            failed_reasons.append("Coverage gate set but no coverage data was provided.")
        else:
            coverage_percent = result.coverage.line_rate * 100.0
            if coverage_percent < min_coverage:
                failed_reasons.append(
                    f"Coverage {coverage_percent:.2f}% is below min_coverage={min_coverage:.2f}%"
                )

    return (len(failed_reasons) == 0, failed_reasons)
