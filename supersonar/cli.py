from __future__ import annotations

import argparse
from collections import Counter
import sys

from supersonar import __version__
from supersonar.baseline import filter_new_issues, load_baseline_fingerprints
from supersonar.config import Config, load_config
from supersonar.coverage import read_coverage_xml
from supersonar.quality_gate import evaluate_gate
from supersonar.reporters import to_json_report, to_sarif_report, write_report
from supersonar.scanner import scan_path
from supersonar.security import resolve_enabled_rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="supersonar", description="Universal static analysis scanner.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run static analysis scan.")
    scan.add_argument("path", nargs="?", default=".", help="Path to scan.")
    scan.add_argument("--config", help="Path to supersonar TOML config.")
    scan.add_argument("--exclude", action="append", default=[], help="Extra exclude directory names.")
    scan.add_argument("--include-ext", action="append", default=[], help="Extension to include (repeatable).")
    scan.add_argument("--include-file", action="append", default=[], help="Filename to include (repeatable).")
    scan.add_argument("--enable-rule", action="append", default=[], help="Only allow specific rule IDs.")
    scan.add_argument("--disable-rule", action="append", default=[], help="Disable specific rule IDs.")
    scan.add_argument(
        "--security-only",
        action="store_true",
        help="Enable only security-focused rules (reduces quality/style noise).",
    )
    scan.add_argument("--no-inline-ignore", action="store_true", help="Disable inline suppression comments.")
    scan.add_argument(
        "--include-generated",
        action="store_true",
        help="Include generated/build artifacts (disabled by default).",
    )
    scan.add_argument("--max-file-size-kb", type=int, help="Skip files larger than this size in KB.")
    scan.add_argument("--format", choices=["json", "sarif"], help="Report output format.")
    scan.add_argument("--out", help="Write report to file. Defaults to stdout.")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Fail on severity level.")
    scan.add_argument("--max-issues", type=int, help="Fail if issue count exceeds this number.")
    scan.add_argument("--max-files-with-issues", type=int, help="Fail if affected file count exceeds this number.")
    scan.add_argument("--max-low", type=int, help="Maximum allowed low-severity issues.")
    scan.add_argument("--max-medium", type=int, help="Maximum allowed medium-severity issues.")
    scan.add_argument("--max-high", type=int, help="Maximum allowed high-severity issues.")
    scan.add_argument("--max-critical", type=int, help="Maximum allowed critical-severity issues.")
    scan.add_argument("--coverage-xml", help="Path to Cobertura coverage.xml file.")
    scan.add_argument("--min-coverage", type=float, help="Minimum required line coverage percentage (0-100).")
    scan.add_argument("--baseline-report", help="Path to a previous supersonar JSON report for baseline comparison.")
    scan.add_argument(
        "--gate-new-only",
        action="store_true",
        help="Evaluate quality gates against new issues only when baseline report is set.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        exit_code = run_scan(args)
        raise SystemExit(exit_code)


def run_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    merged = merge_cli_with_config(args, config)
    validation_errors = validate_quality_gate_config(merged)
    if validation_errors:
        for error in validation_errors:
            print(f"[gate] {error}", file=sys.stderr)
        return 2

    coverage = None
    if merged.scan.coverage_xml:
        coverage = read_coverage_xml(merged.scan.coverage_xml)

    result = scan_path(
        args.path,
        excludes=merged.scan.exclude,
        include_extensions=merged.scan.include_extensions,
        include_filenames=merged.scan.include_filenames,
        max_file_size_kb=merged.scan.max_file_size_kb,
        coverage=coverage,
        skip_generated=merged.scan.skip_generated,
        enabled_rules=resolve_enabled_rules(merged.scan.enabled_rules, merged.scan.security_only),
        disabled_rules=merged.scan.disabled_rules,
        inline_ignore=merged.scan.inline_ignore,
    )
    report_payload = render_report(result, merged.report.output_format)
    write_report(report_payload, merged.report.out)
    print_summary(result)

    gate_result = result
    if merged.quality_gate.baseline_report:
        fingerprints = load_baseline_fingerprints(merged.quality_gate.baseline_report)
        new_result, baseline_matched = filter_new_issues(result, fingerprints)
        print(
            "[baseline] "
            f"total={len(result.issues)} baseline_matches={baseline_matched} new={len(new_result.issues)}",
            file=sys.stderr,
        )
        if merged.quality_gate.only_new_issues:
            gate_result = new_result

    passed, reasons = evaluate_gate(
        gate_result,
        fail_on=merged.quality_gate.fail_on,
        max_issues=merged.quality_gate.max_issues,
        max_files_with_issues=merged.quality_gate.max_files_with_issues,
        max_low=merged.quality_gate.max_low,
        max_medium=merged.quality_gate.max_medium,
        max_high=merged.quality_gate.max_high,
        max_critical=merged.quality_gate.max_critical,
        min_coverage=merged.quality_gate.min_coverage,
    )
    if not passed:
        for reason in reasons:
            print(f"[gate] {reason}", file=sys.stderr)
        return 2
    return 0


def merge_cli_with_config(args: argparse.Namespace, config: Config) -> Config:
    merged = config
    if args.exclude:
        merged.scan.exclude = list(dict.fromkeys([*merged.scan.exclude, *args.exclude]))
    if args.include_ext:
        merged.scan.include_extensions = list(dict.fromkeys([*merged.scan.include_extensions, *args.include_ext]))
    if args.include_file:
        merged.scan.include_filenames = list(dict.fromkeys([*merged.scan.include_filenames, *args.include_file]))
    if args.enable_rule:
        merged.scan.enabled_rules = list(
            dict.fromkeys([*(merged.scan.enabled_rules or []), *(rule.upper() for rule in args.enable_rule)])
        )
    if args.disable_rule:
        merged.scan.disabled_rules = list(
            dict.fromkeys([*merged.scan.disabled_rules, *(rule.upper() for rule in args.disable_rule)])
        )
    if args.no_inline_ignore:
        merged.scan.inline_ignore = False
    if args.security_only:
        merged.scan.security_only = True
    if args.include_generated:
        merged.scan.skip_generated = False
    if args.max_file_size_kb is not None:
        merged.scan.max_file_size_kb = args.max_file_size_kb
    if args.coverage_xml:
        merged.scan.coverage_xml = args.coverage_xml
    if args.format:
        merged.report.output_format = args.format
    if args.out:
        merged.report.out = args.out
    if args.fail_on:
        merged.quality_gate.fail_on = args.fail_on
    if args.max_issues is not None:
        merged.quality_gate.max_issues = args.max_issues
    if args.max_files_with_issues is not None:
        merged.quality_gate.max_files_with_issues = args.max_files_with_issues
    if args.max_low is not None:
        merged.quality_gate.max_low = args.max_low
    if args.max_medium is not None:
        merged.quality_gate.max_medium = args.max_medium
    if args.max_high is not None:
        merged.quality_gate.max_high = args.max_high
    if args.max_critical is not None:
        merged.quality_gate.max_critical = args.max_critical
    if args.min_coverage is not None:
        merged.quality_gate.min_coverage = args.min_coverage
    if args.baseline_report:
        merged.quality_gate.baseline_report = args.baseline_report
    if args.gate_new_only:
        merged.quality_gate.only_new_issues = True
    return merged


def render_report(result, output_format: str):
    if output_format == "sarif":
        return to_sarif_report(result)
    if output_format == "json":
        return to_json_report(result)
    raise ValueError(f"Unsupported report format: {output_format}")


def print_summary(result) -> None:
    counts = Counter(issue.severity for issue in result.issues)
    line = (
        f"[summary] files={result.files_scanned} issues={len(result.issues)} "
        f"low={counts.get('low', 0)} medium={counts.get('medium', 0)} "
        f"high={counts.get('high', 0)} critical={counts.get('critical', 0)}"
    )
    if result.coverage is not None:
        line += f" coverage={result.coverage.line_rate * 100.0:.2f}%"
    print(line, file=sys.stderr)


def validate_quality_gate_config(config: Config) -> list[str]:
    errors: list[str] = []
    if config.quality_gate.fail_on is not None and config.quality_gate.fail_on not in {
        "low",
        "medium",
        "high",
        "critical",
    }:
        errors.append("fail_on must be one of: low, medium, high, critical")

    numeric_gate_values: list[tuple[str, int | None]] = [
        ("max_issues", config.quality_gate.max_issues),
        ("max_files_with_issues", config.quality_gate.max_files_with_issues),
        ("max_low", config.quality_gate.max_low),
        ("max_medium", config.quality_gate.max_medium),
        ("max_high", config.quality_gate.max_high),
        ("max_critical", config.quality_gate.max_critical),
    ]
    for gate_name, value in numeric_gate_values:
        if value is not None and value < 0:
            errors.append(f"{gate_name} must be >= 0")

    if config.quality_gate.min_coverage is not None:
        if config.quality_gate.min_coverage < 0 or config.quality_gate.min_coverage > 100:
            errors.append("min_coverage must be between 0 and 100")
    if config.quality_gate.only_new_issues and not config.quality_gate.baseline_report:
        errors.append("only_new_issues requires baseline_report")
    if config.scan.enabled_rules is not None and len(config.scan.enabled_rules) == 0:
        errors.append("enabled_rules must be non-empty when set")

    return errors


if __name__ == "__main__":
    main()
