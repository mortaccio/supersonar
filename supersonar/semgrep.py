from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from supersonar.models import Issue
from supersonar.security import SEMGREP_RULE_PREFIX

DEFAULT_SEMGREP_CONFIGS = ["p/default"]


def run_semgrep_scan(
    root_path: Path,
    excludes: list[str],
    semgrep_binary: str,
    semgrep_configs: list[str] | None = None,
) -> list[Issue]:
    executable = _resolve_semgrep_binary(semgrep_binary)
    scan_cwd = root_path if root_path.is_dir() else root_path.parent
    target = "." if root_path.is_dir() else root_path.name
    configs = semgrep_configs or DEFAULT_SEMGREP_CONFIGS

    command = [executable, "scan", "--json"]
    for config in configs:
        command.extend(["--config", config])
    for exclude in excludes:
        command.extend(["--exclude", exclude])
    command.append(target)

    completed = subprocess.run(
        command,
        cwd=str(scan_cwd),
        capture_output=True,
        text=True,
        check=False,
    )

    stdout = completed.stdout.strip()
    if not stdout:
        if completed.returncode == 0:
            return []
        stderr = completed.stderr.strip() or f"Semgrep exited with code {completed.returncode}."
        raise OSError(f"Semgrep scan failed: {stderr}")

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse Semgrep JSON output: {exc.msg}") from exc

    issues = [
        issue
        for finding in payload.get("results", [])
        if isinstance(finding, dict)
        for issue in [_finding_to_issue(finding, scan_cwd)]
        if issue is not None
    ]
    if issues or completed.returncode == 0:
        return issues

    errors = payload.get("errors", [])
    if isinstance(errors, list):
        messages = [
            message
            for error in errors
            if isinstance(error, dict)
            for message in [_coerce_text(error.get("message")) or _coerce_text(error.get("type"))]
            if message
        ]
        if messages:
            raise OSError(f"Semgrep scan failed: {'; '.join(messages)}")

    stderr = completed.stderr.strip() or f"Semgrep exited with code {completed.returncode}."
    raise OSError(f"Semgrep scan failed: {stderr}")


def _resolve_semgrep_binary(semgrep_binary: str) -> str:
    candidate = Path(semgrep_binary)
    if candidate.is_absolute() or "/" in semgrep_binary or "\\" in semgrep_binary:
        if candidate.exists():
            return str(candidate)
        raise FileNotFoundError(f"Semgrep executable not found: {semgrep_binary}")

    resolved = shutil.which(semgrep_binary)
    if resolved is None:
        raise FileNotFoundError(
            "Semgrep executable not found. Install it with `pip install semgrep` "
            "or point `--semgrep-bin` to the binary."
        )
    return resolved


def _finding_to_issue(finding: dict[str, Any], scan_cwd: Path) -> Issue | None:
    check_id = _coerce_text(finding.get("check_id"))
    path_value = _coerce_text(finding.get("path"))
    if not check_id or not path_value:
        return None

    extra = finding.get("extra")
    extra_map = extra if isinstance(extra, dict) else {}
    metadata = extra_map.get("metadata")
    metadata_map = metadata if isinstance(metadata, dict) else {}
    start = finding.get("start")
    start_map = start if isinstance(start, dict) else {}

    source_file_path = Path(path_value)
    if not source_file_path.is_absolute():
        source_file_path = (scan_cwd / source_file_path).resolve()

    title = (
        _coerce_text(metadata_map.get("short_description"))
        or _coerce_text(metadata_map.get("shortDescription"))
        or check_id
    )
    message = _coerce_text(extra_map.get("message")) or check_id
    severity = _map_semgrep_severity(
        _coerce_text(extra_map.get("severity")) or _coerce_text(metadata_map.get("severity"))
    )

    return Issue(
        rule_id=f"{SEMGREP_RULE_PREFIX}{check_id}",
        title=title,
        severity=severity,
        message=message,
        file_path=str(source_file_path),
        line=_coerce_int(start_map.get("line"), 1),
        column=_coerce_int(start_map.get("col"), 1),
    )


def _map_semgrep_severity(severity: str | None) -> str:
    normalized = (severity or "").strip().upper()
    mapping = {
        "INFO": "low",
        "INVENTORY": "low",
        "LOW": "low",
        "WARNING": "medium",
        "MEDIUM": "medium",
        "ERROR": "high",
        "HIGH": "high",
        "CRITICAL": "critical",
    }
    return mapping.get(normalized, "medium")


def _coerce_text(value: object) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _coerce_int(value: object, default: int) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return default
