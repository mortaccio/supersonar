from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

from supersonar.models import Severity


DEFAULT_EXCLUDES = [".git", ".venv", "venv", "build", "dist", "__pycache__"]
DEFAULT_INCLUDE_EXTENSIONS = [
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".go",
    ".rs",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".cs",
    ".php",
    ".rb",
    ".swift",
    ".scala",
    ".sql",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".dockerfile",
    ".md",
]
DEFAULT_INCLUDE_FILENAMES = ["Dockerfile", "Jenkinsfile", "Makefile", "Vagrantfile", ".env"]


@dataclass(slots=True)
class ScanConfig:
    exclude: list[str] = field(default_factory=lambda: DEFAULT_EXCLUDES.copy())
    coverage_xml: str | None = None
    include_extensions: list[str] = field(default_factory=lambda: DEFAULT_INCLUDE_EXTENSIONS.copy())
    include_filenames: list[str] = field(default_factory=lambda: DEFAULT_INCLUDE_FILENAMES.copy())
    max_file_size_kb: int = 1024
    skip_generated: bool = True
    enabled_rules: list[str] | None = None
    disabled_rules: list[str] = field(default_factory=list)
    inline_ignore: bool = True


@dataclass(slots=True)
class QualityGateConfig:
    fail_on: Severity | None = None
    max_issues: int | None = None
    max_files_with_issues: int | None = None
    max_low: int | None = None
    max_medium: int | None = None
    max_high: int | None = None
    max_critical: int | None = None
    min_coverage: float | None = None
    baseline_report: str | None = None
    only_new_issues: bool = False


@dataclass(slots=True)
class ReportConfig:
    output_format: str = "json"
    out: str | None = None


@dataclass(slots=True)
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    quality_gate: QualityGateConfig = field(default_factory=QualityGateConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


def load_config(path: str | None) -> Config:
    if path is None:
        default = Path("supersonar.toml")
        if not default.exists():
            return Config()
        path = str(default)

    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config file not found: {cfg_path}")

    with cfg_path.open("rb") as fh:
        payload = tomllib.load(fh)

    scan = payload.get("scan", {})
    quality_gate = payload.get("quality_gate", {})
    report = payload.get("report", {})

    config = Config()
    config.scan.exclude = list(scan.get("exclude", config.scan.exclude))
    config.scan.coverage_xml = scan.get("coverage_xml")
    config.scan.include_extensions = list(scan.get("include_extensions", config.scan.include_extensions))
    config.scan.include_filenames = list(scan.get("include_filenames", config.scan.include_filenames))
    config.scan.max_file_size_kb = int(scan.get("max_file_size_kb", config.scan.max_file_size_kb))
    config.scan.skip_generated = bool(scan.get("skip_generated", config.scan.skip_generated))
    enabled_rules = scan.get("enabled_rules")
    config.scan.enabled_rules = [str(rule).upper() for rule in enabled_rules] if enabled_rules is not None else None
    config.scan.disabled_rules = [str(rule).upper() for rule in scan.get("disabled_rules", config.scan.disabled_rules)]
    config.scan.inline_ignore = bool(scan.get("inline_ignore", config.scan.inline_ignore))
    config.quality_gate.fail_on = quality_gate.get("fail_on")
    config.quality_gate.max_issues = quality_gate.get("max_issues")
    config.quality_gate.max_files_with_issues = quality_gate.get("max_files_with_issues")
    config.quality_gate.max_low = quality_gate.get("max_low")
    config.quality_gate.max_medium = quality_gate.get("max_medium")
    config.quality_gate.max_high = quality_gate.get("max_high")
    config.quality_gate.max_critical = quality_gate.get("max_critical")
    config.quality_gate.min_coverage = quality_gate.get("min_coverage")
    config.quality_gate.baseline_report = quality_gate.get("baseline_report")
    config.quality_gate.only_new_issues = bool(quality_gate.get("only_new_issues", config.quality_gate.only_new_issues))
    config.report.output_format = report.get("format", config.report.output_format)
    config.report.out = report.get("out")
    return config
