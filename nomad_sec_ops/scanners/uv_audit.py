"""Run uv's lockfile audit and validate its JSON report."""

import json
import subprocess
from pathlib import Path

from nomad_sec_ops.models import AnalysisStatus, CheckResult, DependencyAudit


def run_uv_audit(root: Path) -> CheckResult:
    result = subprocess.run(
        [
            "uv",
            "--no-config",
            "--directory",
            str(root.absolute()),
            "--project",
            str(root.absolute()),
            "audit",
            "--frozen",
            "--no-python-downloads",
            "--preview-features",
            "audit,json-output",
            "--output-format",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    try:
        if result.returncode not in {0, 1} or not result.stdout.strip():
            raise ValueError(f"uv exited with code {result.returncode}")
        output = json.loads(result.stdout)
        summary = output["summary"]
        audit = DependencyAudit(
            audited_packages=summary["audited_packages"],
            vulnerabilities=output["vulnerabilities"],
            adverse_statuses=output["adverse_statuses"],
        )
        vulnerability_count = len(audit.vulnerabilities)
        adverse_count = len(audit.adverse_statuses)
        if (
            summary["vulnerabilities"] != vulnerability_count
            or summary["adverse_statuses"] != adverse_count
            or result.returncode != int(vulnerability_count > 0)
        ):
            raise ValueError("report counts do not match its findings or exit code")
    except (KeyError, TypeError, ValueError) as error:
        return CheckResult(
            status=AnalysisStatus.ERROR,
            message=f"uv audit failed ({error}).",
            tool="uv",
            stderr=result.stderr,
        )

    status = AnalysisStatus.FINDINGS if vulnerability_count else AnalysisStatus.PASSED
    return CheckResult(
        status=status,
        message=(
            f"uv audit checked {audit.audited_packages} package(s) "
            f"(vulnerabilities: {vulnerability_count}, "
            f"adverse project statuses: {adverse_count})."
        ),
        tool="uv",
        stderr=result.stderr,
        dependency_audit=audit,
    )
