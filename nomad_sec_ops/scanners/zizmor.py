"""GitHub CI/CD scanner adapter; no repository-wide orchestration lives here."""

import subprocess

from nomad_sec_ops.models import AnalysisStatus, CheckResult


def run_zizmor(target: str) -> CheckResult:
    result = subprocess.run(
        ["zizmor", "--format=plain", "--gh-hostname=github.com", "--", target],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode == 0:
        status = AnalysisStatus.PASSED
        message = "zizmor: no findings."
    elif result.returncode in {11, 12, 13, 14}:
        status = AnalysisStatus.FINDINGS
        message = "zizmor: security findings detected."
    elif result.returncode == 3:
        status = AnalysisStatus.NOT_EVALUATED
        message = "zizmor not evaluated: no supported inputs were found."
    else:
        status = AnalysisStatus.ERROR
        message = f"zizmor failed with exit code {result.returncode}."
    return CheckResult(
        status=status,
        message=message,
        tool="zizmor",
        stdout=result.stdout,
        stderr=result.stderr,
    )
