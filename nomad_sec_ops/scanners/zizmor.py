"""GitHub CI/CD scanner adapter; no repository-wide orchestration lives here."""

import os
import subprocess
from pathlib import Path

from nomad_sec_ops.models import AnalysisStatus, CheckResult


def run_zizmor(target: str, *, config_path: Path | None = None) -> CheckResult:
    config_args = (
        ["--no-config"] if config_path is None else ["--config", str(config_path)]
    )
    env = os.environ.copy()
    # zizmor treats ZIZMOR_CONFIG as --config, which conflicts with --no-config.
    env.pop("ZIZMOR_CONFIG", None)
    result = subprocess.run(
        [
            "zizmor",
            "--quiet",
            "--offline",
            "--format=plain",
            "--gh-hostname=github.com",
            *config_args,
            "--no-ignores",
            "--",
            target,
        ],
        env=env,
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
