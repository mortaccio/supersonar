from __future__ import annotations

import argparse
from collections import Counter
import sys

from supersonar.config import Config, load_config
from supersonar.coverage import read_coverage_xml
from supersonar.quality_gate import evaluate_gate
from supersonar.reporters import to_json_report, to_sarif_report, write_report
from supersonar.scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="supersonar", description="Universal static analysis scanner.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run static analysis scan.")
    scan.add_argument("path", nargs="?", default=".", help="Path to scan.")
    scan.add_argument("--config", help="Path to supersonar TOML config.")
    scan.add_argument("--exclude", action="append", default=[], help="Extra exclude directory names.")
    scan.add_argument("--include-ext", action="append", default=[], help="Extension to include (repeatable).")
    scan.add_argument("--include-file", action="append", default=[], help="Filename to include (repeatable).")
    scan.add_argument("--max-file-size-kb", type=int, help="Skip files larger than this size in KB.")
    scan.add_argument("--format", choices=["json", "sarif"], help="Report output format.")
    scan.add_argument("--out", help="Write report to file. Defaults to stdout.")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Fail on severity level.")
    scan.add_argument("--max-issues", type=int, help="Fail if issue count exceeds this number.")
    scan.add_argument("--max-low", type=int, help="Maximum allowed low-severity issues.")
    scan.add_argument("--max-medium", type=int, help="Maximum allowed medium-severity issues.")
    scan.add_argument("--max-high", type=int, help="Maximum allowed high-severity issues.")
    scan.add_argument("--max-critical", type=int, help="Maximum allowed critical-severity issues.")
    scan.add_argument("--coverage-xml", help="Path to Cobertura coverage.xml file.")
    scan.add_argument("--min-coverage", type=float, help="Minimum required line coverage percentage (0-100).")

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
    if merged.quality_gate.min_coverage is not None:
        if merged.quality_gate.min_coverage < 0 or merged.quality_gate.min_coverage > 100:
            print("[gate] min_coverage must be between 0 and 100", file=sys.stderr)
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
    )
    report_payload = render_report(result, merged.report.output_format)
    write_report(report_payload, merged.report.out)
    print_summary(result)

    passed, reasons = evaluate_gate(
        result,
        fail_on=merged.quality_gate.fail_on,
        max_issues=merged.quality_gate.max_issues,
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


if __name__ == "__main__":
    main()
